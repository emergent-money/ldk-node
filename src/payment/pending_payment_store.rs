// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use bitcoin::Txid;
use lightning::io::Read;
use lightning::ln::channelmanager::PaymentId;
use lightning::ln::msgs::DecodeError;
use lightning::util::ser::{BigSize, Readable, Writeable, Writer};
use lightning::{_decode_and_build, impl_writeable_tlv_based, write_tlv_fields};

use crate::data_store::{StorableObject, StorableObjectUpdate, UpdatableObject};
use crate::payment::store::{Channel, PaymentDetailsUpdate, TransactionType};
use crate::payment::{PaymentDetails, PaymentKind};

/// One candidate transaction in an interactive-funding (splice) RBF history, holding this node's
/// share of the funding amount and fee for that candidate. Both are `None` for a candidate this
/// node did not contribute to — e.g. a counterparty-initiated round before our `splice_in` joined
/// it via RBF. Recorded per pending payment so that, on confirmation, the payment reports the
/// figures of the candidate that actually confirmed, which need not be the last one broadcast.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FundingTxCandidate {
	/// The candidate's broadcast transaction id.
	pub txid: Txid,
	/// This node's share of the funding amount for this candidate, in millisatoshis, or `None` if
	/// this node did not contribute to it.
	pub amount_msat: Option<u64>,
	/// This node's share of the on-chain fee for this candidate, in millisatoshis, or `None` if
	/// this node did not contribute to it.
	pub fee_paid_msat: Option<u64>,
	/// Whether this node signed the candidate but LDK has yet to report the round negotiated. Set
	/// when the round is recorded at signing time, cleared when LDK reports the splice negotiated
	/// (`SpliceNegotiated`, emitted only once our `tx_signatures` for the round are ready to send).
	/// Such a round may be abandoned without a trace — the counterparty aborts, or the channel
	/// closes, before the signatures are exchanged — so only such a round may be dropped from the
	/// history, and only once LDK no longer tracks it.
	pub awaiting_broadcast: bool,
}

impl_writeable_tlv_based!(FundingTxCandidate, {
	(0, txid, required),
	(2, amount_msat, option),
	(4, fee_paid_msat, option),
	(6, awaiting_broadcast, required),
});

/// A pending payment tracked by LDK Node, keyed by [`PaymentId`].
///
/// Each part of an entry is written by a different subsystem and is present on its own schedule,
/// so all of them are optional. Signing a round of an interactive funding adds the round to
/// `candidates` and lists the `funding_channels` it belongs to, still without a transaction anyone
/// has seen; wallet sync adds `details` once it observes the transaction, and records
/// `conflicting_txids` for any wallet transaction. A splice uses all of them; the fields do not
/// partition by payment type. An entry with none of them tracks no payment and is removed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PendingPaymentDetails {
	/// The payment this entry tracks.
	pub id: PaymentId,
	/// The full payment details, or `None` for a splice whose transaction wallet sync has yet to
	/// observe — including one this node has signed that was never broadcast.
	pub details: Option<PaymentDetails>,
	/// Transaction IDs wallet sync observed to have replaced or to conflict with this
	/// payment, used to map later events about those txids back to this record. This is
	/// BDK's view, distinct from `candidates`: it can list conflicts that were never
	/// negotiated candidates, while a candidate replaced between wallet syncs may never
	/// appear here (it gets no `TxReplaced` event of its own).
	pub conflicting_txids: Vec<Txid>,
	/// The channels whose interactive funding `candidates` are rounds of, as the signing of a
	/// round recorded them. Empty for a non-funding payment and for a record wallet sync created
	/// on its own, whose channels its classification lists instead.
	pub funding_channels: Vec<Channel>,
	/// For interactive funding (splices), this node's per-candidate funding figures across the
	/// RBF history, keyed by each candidate's txid and recorded as each round is signed.
	/// Empty for non-funding payments.
	pub candidates: Vec<FundingTxCandidate>,
	/// The candidates LDK promoted to the channel's funding, as `ChannelReady` reported them.
	/// A zero-conf splice locks before its transaction confirms, and every later splice builds
	/// on it, so such a round can still confirm once the channel's funding has moved on from
	/// it and once the channel has closed, when LDK no longer tracks it. Kept apart from the
	/// candidates, which each funding-record write replaces as a whole.
	pub locked_rounds: Vec<Txid>,
}

impl PendingPaymentDetails {
	pub(crate) fn new(
		details: PaymentDetails, conflicting_txids: Vec<Txid>, candidates: Vec<FundingTxCandidate>,
	) -> Self {
		Self {
			id: details.id,
			details: Some(details),
			conflicting_txids,
			funding_channels: Vec::new(),
			candidates,
			locked_rounds: Vec::new(),
		}
	}

	/// An entry for the rounds of an interactive funding of `funding_channels` this node has
	/// signed, before any transaction of it has been observed and therefore before a payment
	/// record for it exists.
	pub(crate) fn signed_rounds(
		id: PaymentId, funding_channels: Vec<Channel>, candidates: Vec<FundingTxCandidate>,
	) -> Self {
		Self {
			id,
			details: None,
			conflicting_txids: Vec::new(),
			funding_channels,
			candidates,
			locked_rounds: Vec::new(),
		}
	}

	/// The full payment details, or `None` for a splice whose transaction has not been observed.
	pub(crate) fn details(&self) -> Option<&PaymentDetails> {
		self.details.as_ref()
	}

	/// Transaction IDs that have replaced or conflict with this payment.
	pub(crate) fn conflicting_txids(&self) -> &[Txid] {
		&self.conflicting_txids
	}

	/// The rounds LDK promoted to the channel's funding, as `ChannelReady` reported them.
	pub(crate) fn locked_rounds(&self) -> &[Txid] {
		&self.locked_rounds
	}

	/// Records that LDK promoted the round with the given txid to the channel's funding. Returns
	/// whether the record changed: a round recorded as promoted already leaves it as it is.
	pub(crate) fn record_locked_round(&mut self, txid: Txid) -> bool {
		if self.locked_rounds.contains(&txid) {
			return false;
		}
		self.locked_rounds.push(txid);
		true
	}

	/// Returns this node's recorded funding figures for the candidate with the given txid, if any.
	pub(crate) fn candidate(&self, txid: Txid) -> Option<&FundingTxCandidate> {
		self.candidates.iter().find(|candidate| candidate.txid == txid)
	}

	/// This node's recorded funding figures across the candidate history, in LDK's order; empty
	/// for a splice without a signed round yet and for non-funding payments.
	pub(crate) fn candidates(&self) -> &[FundingTxCandidate] {
		&self.candidates
	}

	/// The channels of the interactive funding this entry tracks: those the signing of a round
	/// recorded, else those its classification lists.
	pub(crate) fn funding_channels(&self) -> &[Channel] {
		if !self.funding_channels.is_empty() {
			return &self.funding_channels;
		}
		match self.details.as_ref().map(|details| &details.kind) {
			Some(PaymentKind::Onchain {
				tx_type: Some(TransactionType::InteractiveFunding { channels }),
				..
			}) => channels,
			_ => &[],
		}
	}

	/// Whether this entry tracks nothing anymore and can be dropped.
	pub(crate) fn is_empty(&self) -> bool {
		self.details.is_none() && self.candidates.is_empty() && self.locked_rounds.is_empty()
	}
}

impl Writeable for PendingPaymentDetails {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
		// The layout `impl_writeable_tlv_based!` generated, unchanged. It is spelled out only because
		// the macro would also generate a `Readable`, and the one below reads the legacy layout too.
		write_tlv_fields!(writer, {
			(0, self.id, required),
			(2, self.details, option),
			(4, self.conflicting_txids, optional_vec),
			(6, self.funding_channels, optional_vec),
			(8, self.candidates, optional_vec),
			(12, self.locked_rounds, optional_vec),
		});
		Ok(())
	}
}

impl Readable for PendingPaymentDetails {
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
		// Both layouts are a length-prefixed TLV stream: a `BigSize` length, then that many bytes of
		// TLV records. Buffer the stream, so that its first record can tell the layout before either
		// decodes it.
		let len: BigSize = Readable::read(reader)?;
		let mut stream = len.encode();
		let records_start = stream.len();
		let records_read = reader.read_to_limit(&mut stream, len.0)?;
		if records_read as u64 != len.0 {
			return Err(DecodeError::ShortRead);
		}

		let reader = &mut &stream[..];
		if starts_with_payment_id(&stream[records_start..]) {
			Ok(_decode_and_build!(reader, Self, {
				(0, id, required),
				(2, details, option),
				(4, conflicting_txids, optional_vec),
				(6, funding_channels, optional_vec),
				(8, candidates, optional_vec),
				(12, locked_rounds, optional_vec),
			}))
		} else {
			// Not the id-keyed layout, so the legacy one or nothing: an entry whose payment record
			// fails to decode fails the read rather than being dropped.
			let legacy: LegacyPendingPaymentDetails = Readable::read(reader)?;
			Ok(legacy.into())
		}
	}
}

/// Whether the given TLV records open with a 32-byte record of type 0, as an entry in the id-keyed
/// layout does with its [`PaymentId`]. An entry in the legacy layout opens with type 0 too, but
/// holding its length-prefixed [`PaymentDetails`], whose own id record alone takes 34 bytes.
fn starts_with_payment_id(mut records: &[u8]) -> bool {
	let first_type: Result<BigSize, DecodeError> = Readable::read(&mut records);
	let first_len: Result<BigSize, DecodeError> = Readable::read(&mut records);
	matches!((first_type, first_len), (Ok(BigSize(0)), Ok(BigSize(32))))
}

/// A [`FundingTxCandidate`] as an entry in the legacy layout recorded it: once the round was
/// broadcast, so never awaiting broadcast.
struct LegacyFundingTxCandidate {
	txid: Txid,
	amount_msat: Option<u64>,
	fee_paid_msat: Option<u64>,
}

impl_writeable_tlv_based!(LegacyFundingTxCandidate, {
	(0, txid, required),
	(2, amount_msat, option),
	(4, fee_paid_msat, option),
});

impl From<LegacyFundingTxCandidate> for FundingTxCandidate {
	fn from(legacy: LegacyFundingTxCandidate) -> Self {
		let LegacyFundingTxCandidate { txid, amount_msat, fee_paid_msat } = legacy;
		Self { txid, amount_msat, fee_paid_msat, awaiting_broadcast: false }
	}
}

/// A [`PendingPaymentDetails`] in the layout written before entries were keyed by their own id and
/// before signing a round recorded it (LDK Node 0cea341 and earlier; no release shipped it). Every
/// entry then held its payment record, under type 0, and was keyed by that payment's id.
struct LegacyPendingPaymentDetails {
	details: PaymentDetails,
	conflicting_txids: Vec<Txid>,
	candidates: Vec<LegacyFundingTxCandidate>,
}

impl_writeable_tlv_based!(LegacyPendingPaymentDetails, {
	(0, details, required),
	(2, conflicting_txids, optional_vec),
	(4, candidates, optional_vec),
});

impl From<LegacyPendingPaymentDetails> for PendingPaymentDetails {
	/// Keys the entry by its payment's id. It recorded no channels for its rounds, whose payment's
	/// classification lists them, and no rounds LDK promoted. It is rewritten in the id-keyed
	/// layout on its next update.
	fn from(legacy: LegacyPendingPaymentDetails) -> Self {
		let LegacyPendingPaymentDetails { details, conflicting_txids, candidates } = legacy;
		let candidates = candidates.into_iter().map(FundingTxCandidate::from).collect();
		Self::new(details, conflicting_txids, candidates)
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PendingPaymentDetailsUpdate {
	pub id: PaymentId,
	pub payment_update: Option<PaymentDetailsUpdate>,
	pub conflicting_txids: Option<Vec<Txid>>,
	pub candidates: Vec<FundingTxCandidate>,
}

impl StorableObject for PendingPaymentDetails {
	type Id = PaymentId;

	fn id(&self) -> Self::Id {
		self.id
	}
}

impl UpdatableObject for PendingPaymentDetails {
	type Update = PendingPaymentDetailsUpdate;

	fn update(&mut self, update: Self::Update) -> bool {
		let mut updated = false;

		// Update the underlying payment details if present. An entry with no record yet is not
		// given one here: only the writer that observed the transaction knows what the record
		// says, and it sets the field directly.
		if let (Some(payment_update), Some(details)) =
			(update.payment_update, self.details.as_mut())
		{
			updated |= details.update(payment_update);
		}

		if let Some(new_conflicting_txids) = update.conflicting_txids {
			if self.conflicting_txids != new_conflicting_txids {
				self.conflicting_txids = new_conflicting_txids;
				updated = true;
			}
		}

		if let Some(PaymentKind::Onchain { txid, .. }) =
			self.details.as_ref().map(|details| &details.kind)
		{
			let txid = *txid;
			let conflicts_len = self.conflicting_txids.len();
			self.conflicting_txids.retain(|conflicting_txid| *conflicting_txid != txid);
			updated |= self.conflicting_txids.len() != conflicts_len;
		}

		// Each funding-record write passes the candidate history as of its own round, so a
		// non-empty update replaces the stored list. An empty update (e.g. a non-funding
		// payment) leaves it untouched. Dropping an abandoned round, the only writer that
		// shrinks it, goes through the store's `mutate` instead.
		if !update.candidates.is_empty() && self.candidates != update.candidates {
			self.candidates = update.candidates;
			updated = true;
		}

		updated
	}

	fn to_update(&self) -> Self::Update {
		self.into()
	}
}

impl StorableObjectUpdate<PendingPaymentDetails> for PendingPaymentDetailsUpdate {
	fn id(&self) -> <PendingPaymentDetails as StorableObject>::Id {
		self.id
	}
}

impl From<&PendingPaymentDetails> for PendingPaymentDetailsUpdate {
	fn from(value: &PendingPaymentDetails) -> Self {
		match &value.details {
			// An entry with no record yet carries nothing a payment-tracking merge could apply.
			None => Self {
				id: value.id,
				payment_update: None,
				conflicting_txids: None,
				candidates: value.candidates.clone(),
			},
			Some(details) => {
				let conflicting_txids = if value.conflicting_txids.is_empty() {
					None
				} else {
					Some(value.conflicting_txids.clone())
				};
				Self {
					id: details.id,
					payment_update: Some(details.to_update()),
					conflicting_txids,
					candidates: value.candidates.clone(),
				}
			},
		}
	}
}

/// Builds a [`FundingContribution`] for tests through its `Readable` impl — the only path open
/// outside `rust-lightning`, which keeps its builder private. The length-prefixed stream contains
/// the required TLV records (the given estimated fee in satoshis, feerate, max feerate, and the
/// is-splice flag) plus the given contributed outputs.
///
/// [`FundingContribution`]: lightning::ln::funding::FundingContribution
#[cfg(test)]
pub(crate) fn test_funding_contribution_with_outputs(
	estimated_fee_sat: u64, feerate: u64, outputs: &[bitcoin::TxOut],
) -> lightning::ln::funding::FundingContribution {
	test_funding_contribution_with_parts(estimated_fee_sat, feerate, &[], outputs, None)
}

/// Builds a [`FundingContribution`] for tests from its parts: the given estimated fee, an input
/// spending output 0 — which must be P2WPKH — of each given previous transaction, the given
/// contributed outputs and change output, and the given input-selection feerate (also used as
/// the maximum), with the is-splice flag set.
///
/// [`FundingContribution`]: lightning::ln::funding::FundingContribution
#[cfg(test)]
pub(crate) fn test_funding_contribution_with_parts(
	estimated_fee_sat: u64, feerate: u64, prevtxs: &[bitcoin::Transaction],
	outputs: &[bitcoin::TxOut], change_output: Option<&bitcoin::TxOut>,
) -> lightning::ln::funding::FundingContribution {
	use lightning::util::ser::{BigSize, Writeable};
	use lightning::util::wallet_utils::ConfirmedUtxo;
	let mut records = vec![1, 8]; // (1, estimated_fee)
	records.extend_from_slice(&estimated_fee_sat.to_be_bytes());
	if !prevtxs.is_empty() {
		let mut input_bytes = Vec::new();
		for prevtx in prevtxs {
			ConfirmedUtxo::new_p2wpkh(prevtx.clone(), 0)
				.expect("test prevtx output 0 must be P2WPKH")
				.write(&mut input_bytes)
				.expect("in-memory write must succeed");
		}
		records.push(3); // (3, inputs)
		BigSize(input_bytes.len() as u64)
			.write(&mut records)
			.expect("in-memory write must succeed");
		records.extend_from_slice(&input_bytes);
	}
	if !outputs.is_empty() {
		let mut output_bytes = Vec::new();
		for output in outputs {
			output.write(&mut output_bytes).expect("in-memory write must succeed");
		}
		records.push(5); // (5, outputs)
		BigSize(output_bytes.len() as u64)
			.write(&mut records)
			.expect("in-memory write must succeed");
		records.extend_from_slice(&output_bytes);
	}
	if let Some(change_output) = change_output {
		let change_bytes = change_output.encode();
		records.push(7); // (7, change_output)
		BigSize(change_bytes.len() as u64)
			.write(&mut records)
			.expect("in-memory write must succeed");
		records.extend_from_slice(&change_bytes);
	}
	records.extend_from_slice(&[9, 8]); // (9, feerate)
	records.extend_from_slice(&feerate.to_be_bytes());
	records.extend_from_slice(&[11, 8]); // (11, max_feerate)
	records.extend_from_slice(&feerate.to_be_bytes());
	records.extend_from_slice(&[13, 1, 1]); // (13, is_splice: true)
	let mut tlv_bytes = Vec::new();
	// BigSize length prefix over the TLV records above.
	BigSize(records.len() as u64).write(&mut tlv_bytes).expect("in-memory write must succeed");
	tlv_bytes.extend(records);
	lightning::util::ser::Readable::read(&mut &tlv_bytes[..])
		.expect("hand-built TLV stream must decode")
}

#[cfg(test)]
mod tests {
	use bitcoin::hashes::Hash;
	use lightning::util::ser::{Readable, Writeable};

	use super::*;
	use crate::payment::store::ConfirmationStatus;
	use crate::payment::{PaymentDirection, PaymentKind, PaymentStatus};

	#[test]
	fn pending_payment_candidate_lookup() {
		let payment_id = PaymentId([1u8; 32]);
		let first_txid = Txid::from_byte_array([2u8; 32]);
		let rbf_txid = Txid::from_byte_array([3u8; 32]);

		// A leading counterparty-initiated round we didn't contribute to (no figures), then our own
		// original and RBF candidates.
		let counterparty_txid = Txid::from_byte_array([4u8; 32]);
		let candidates = vec![
			FundingTxCandidate {
				txid: counterparty_txid,
				amount_msat: None,
				fee_paid_msat: None,
				awaiting_broadcast: false,
			},
			FundingTxCandidate {
				txid: first_txid,
				amount_msat: Some(1_000_000),
				fee_paid_msat: Some(1_000),
				awaiting_broadcast: false,
			},
			FundingTxCandidate {
				txid: rbf_txid,
				amount_msat: Some(1_000_000),
				fee_paid_msat: Some(5_000),
				awaiting_broadcast: false,
			},
		];

		// The stored details only need to be a valid funding payment; `candidate` resolves figures
		// purely from the recorded candidate list.
		let details = PaymentDetails::new(
			payment_id,
			PaymentKind::Onchain {
				txid: rbf_txid,
				status: ConfirmationStatus::Unconfirmed,
				tx_type: None,
			},
			Some(1_000_000),
			Some(5_000),
			PaymentDirection::Outbound,
			PaymentStatus::Pending,
		);
		let pending =
			PendingPaymentDetails::new(details, vec![first_txid, counterparty_txid], candidates);

		// Each candidate resolves to its own figures, so a non-last candidate that confirms reports
		// its own (lower) fee rather than the last-broadcast candidate's.
		assert_eq!(pending.candidate(first_txid).and_then(|c| c.fee_paid_msat), Some(1_000));
		assert_eq!(pending.candidate(rbf_txid).and_then(|c| c.fee_paid_msat), Some(5_000));
		// A candidate we didn't contribute to carries no figures, so the payment reports `None`
		// rather than another candidate's stale figures.
		let counterparty = pending.candidate(counterparty_txid).expect("candidate is recorded");
		assert_eq!(counterparty.amount_msat, None);
		assert_eq!(counterparty.fee_paid_msat, None);
		assert_eq!(pending.candidate(Txid::from_byte_array([9u8; 32])), None);
	}

	fn test_txid(byte: u8) -> Txid {
		Txid::from_byte_array([byte; 32])
	}

	fn pending_onchain_payment(payment_id: PaymentId, txid: Txid) -> PaymentDetails {
		PaymentDetails::new(
			payment_id,
			PaymentKind::Onchain { txid, status: ConfirmationStatus::Unconfirmed, tx_type: None },
			Some(1_000),
			Some(100),
			PaymentDirection::Outbound,
			PaymentStatus::Pending,
		)
	}

	#[test]
	fn pending_onchain_conflicts_exclude_current_txid_after_txid_rotation() {
		let original_txid = test_txid(1);
		let replacement_txid = test_txid(2);
		let payment_id = PaymentId(original_txid.to_byte_array());

		let mut pending_payment = PendingPaymentDetails::new(
			pending_onchain_payment(payment_id, replacement_txid),
			vec![original_txid],
			Vec::new(),
		);
		let update = PendingPaymentDetails::new(
			pending_onchain_payment(payment_id, original_txid),
			Vec::new(),
			Vec::new(),
		)
		.to_update();

		assert!(pending_payment.update(update));
		assert_eq!(
			pending_payment.conflicting_txids(),
			Vec::<Txid>::new(),
			"current txid must not remain in its own conflict list"
		);
	}

	/// A candidate with the given txid byte, with a stake of ours in it if `ours`.
	fn candidate(txid_byte: u8, ours: bool) -> FundingTxCandidate {
		FundingTxCandidate {
			txid: test_txid(txid_byte),
			amount_msat: ours.then_some(1_000),
			fee_paid_msat: ours.then_some(100),
			awaiting_broadcast: false,
		}
	}

	fn entry(candidates: Vec<FundingTxCandidate>) -> PendingPaymentDetails {
		let payment_id = PaymentId([1u8; 32]);
		let txid = candidates.last().expect("at least one candidate").txid;
		PendingPaymentDetails::new(pending_onchain_payment(payment_id, txid), vec![], candidates)
	}

	/// An entry written by a node from before the rounds LDK promoted were kept on it reads as an
	/// entry with none, everything else intact.
	#[test]
	fn an_entry_written_without_locked_rounds_reads_with_none() {
		let mut stored = entry(vec![candidate(2, false), candidate(3, true)]);
		stored.conflicting_txids = vec![test_txid(9)];

		let write_as_before = || -> Result<Vec<u8>, lightning::io::Error> {
			let mut written = Vec::new();
			lightning::write_tlv_fields!(&mut written, {
				(0, stored.id, required),
				(2, stored.details, option),
				(4, stored.conflicting_txids, optional_vec),
				(6, stored.funding_channels, optional_vec),
				(8, stored.candidates, optional_vec),
			});
			Ok(written)
		};
		let written_before = write_as_before().unwrap();

		let decoded: PendingPaymentDetails = Readable::read(&mut &written_before[..])
			.expect("an entry written before the rounds were kept still reads");
		assert!(decoded.locked_rounds().is_empty());
		assert_eq!(decoded, stored);
	}

	/// The rounds LDK promoted round-trip with the entry, absent or present, and the merge of a
	/// record's full update, as wallet sync writes it, leaves them.
	#[test]
	fn locked_rounds_round_trip_and_survive_a_merge() {
		let mut stored = entry(vec![candidate(2, false)]);
		let decoded: PendingPaymentDetails =
			Readable::read(&mut &stored.encode()[..]).expect("encoding must round-trip");
		assert!(decoded.locked_rounds().is_empty());

		assert!(stored.record_locked_round(test_txid(2)));
		assert!(!stored.record_locked_round(test_txid(2)));
		let decoded: PendingPaymentDetails =
			Readable::read(&mut &stored.encode()[..]).expect("encoding must round-trip");
		assert_eq!(decoded, stored);

		let synced = entry(vec![candidate(2, false), candidate(3, false)]);
		assert!(stored.update(synced.to_update()));
		assert_eq!(stored.candidates().len(), 2);
		assert_eq!(stored.locked_rounds(), &[test_txid(2)]);
	}

	/// Entries a node on LDK Node 0cea341 wrote in the legacy layout, each as the key it is stored
	/// under (its payment's id, in hex), the amount its payment record holds in millisatoshis, and
	/// the entry as stored. Each records an outbound on-chain payment whose transaction (the id)
	/// was unconfirmed when written, with no classification, a zero fee and no conflicts or
	/// candidates.
	const LAB_PIN_ENTRIES: [(&str, u64, &str); 5] = [
		(
			"193a3693fcb69421843acace003b9159ad0ca7a8ea684a7d4767d67786649f3c",
			351_000,
			"7c007a790020193a3693fcb69421843acace003b9159ad0ca7a8ea684a7d4767d67786649f3c020100032800260020193a3693fcb69421843acace003b9159ad0ca7a8ea684a7d4767d67786649f3c020202000401000508000000006aa9df930609090000000000055b1807080000000000000000080201000a020000",
		),
		(
			"369c067a29823bf20fdac1b967cb90810692f5085727cfd55db2d9781bf4612f",
			349_000,
			"7c007a790020369c067a29823bf20fdac1b967cb90810692f5085727cfd55db2d9781bf4612f020100032800260020369c067a29823bf20fdac1b967cb90810692f5085727cfd55db2d9781bf4612f020202000401000508000000006a848b70060909000000000005534807080000000000000000080201000a020000",
		),
		(
			"5bf11b02ace6c60a26c36713d41e6f251c0af64882d6afedbce69533d51c1f74",
			849_000,
			"7c007a7900205bf11b02ace6c60a26c36713d41e6f251c0af64882d6afedbce69533d51c1f740201000328002600205bf11b02ace6c60a26c36713d41e6f251c0af64882d6afedbce69533d51c1f74020202000401000508000000006a84870f06090900000000000cf46807080000000000000000080201000a020000",
		),
		(
			"e7b5041b402d3a1fa7624caab309cf77daac826356116116d6dbb180c54611a9",
			349_000,
			"7c007a790020e7b5041b402d3a1fa7624caab309cf77daac826356116116d6dbb180c54611a9020100032800260020e7b5041b402d3a1fa7624caab309cf77daac826356116116d6dbb180c54611a9020202000401000508000000006a848b70060909000000000005534807080000000000000000080201000a020000",
		),
		(
			"eac9392cc0227ce77338744b6d173195e54ad67209d93c54ae2463866811fb41",
			351_000,
			"7c007a790020eac9392cc0227ce77338744b6d173195e54ad67209d93c54ae2463866811fb41020100032800260020eac9392cc0227ce77338744b6d173195e54ad67209d93c54ae2463866811fb41020202000401000508000000006aa9df930609090000000000055b1807080000000000000000080201000a020000",
		),
	];

	fn decode_hex(hex: &str) -> Vec<u8> {
		crate::hex_utils::to_vec(hex).expect("test hex must be valid")
	}

	#[test]
	fn reads_legacy_pending_payment_records_from_the_lab_pin() {
		for (key, amount_msat, stored) in LAB_PIN_ENTRIES {
			let id = PaymentId(decode_hex(key).try_into().expect("a payment id is 32 bytes"));
			let entry: PendingPaymentDetails = Readable::read(&mut &decode_hex(stored)[..])
				.unwrap_or_else(|e| panic!("entry {} must read: {}", key, e));

			assert_eq!(entry.id, id);
			let details = entry.details().expect("a legacy entry always held its payment record");
			assert_eq!(details.id, id);
			assert!(entry.conflicting_txids().is_empty());
			assert!(entry.funding_channels.is_empty());
			assert!(entry.candidates().is_empty());
			assert!(entry.locked_rounds().is_empty());

			// What each of these entries holds: an outbound on-chain send of `amount_msat` with a
			// zero fee, pending on its unconfirmed transaction, whose txid is the payment id.
			assert_eq!(
				details.kind,
				PaymentKind::Onchain {
					txid: Txid::from_byte_array(id.0),
					status: ConfirmationStatus::Unconfirmed,
					tx_type: None,
				}
			);
			assert_eq!(details.status, PaymentStatus::Pending);
			assert_eq!(details.direction, PaymentDirection::Outbound);
			assert_eq!(details.amount_msat, Some(amount_msat));
			assert_eq!(details.fee_paid_msat, Some(0));

			// The next write of the entry moves it to the id-keyed layout, unchanged.
			let rewritten = entry.encode();
			assert_eq!(rewritten, GeneratedLayout::from(&entry).encode());
			let reread: PendingPaymentDetails =
				Readable::read(&mut &rewritten[..]).expect("a rewritten entry reads");
			assert_eq!(reread, entry);
		}
	}

	fn test_channel() -> Channel {
		let secp = bitcoin::secp256k1::Secp256k1::new();
		let secret_key = bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32])
			.expect("test secret key must be valid");
		Channel {
			counterparty_node_id: bitcoin::secp256k1::PublicKey::from_secret_key(
				&secp,
				&secret_key,
			),
			channel_id: lightning::ln::types::ChannelId::from_bytes([4u8; 32]),
		}
	}

	#[test]
	fn reads_legacy_record_with_conflicts_and_candidates() {
		// A splice joined via RBF, as the legacy layout recorded it at its second round's
		// broadcast: the payment keyed by the first round, a counterparty-initiated round we did
		// not contribute to, then our own.
		let first_txid = test_txid(5);
		let rbf_txid = test_txid(6);
		let payment_id = PaymentId(first_txid.to_byte_array());
		let details = PaymentDetails::new(
			payment_id,
			PaymentKind::Onchain {
				txid: rbf_txid,
				status: ConfirmationStatus::Unconfirmed,
				tx_type: Some(TransactionType::InteractiveFunding {
					channels: vec![test_channel()],
				}),
			},
			Some(1_000_000),
			Some(5_000),
			PaymentDirection::Outbound,
			PaymentStatus::Pending,
		);
		let legacy = LegacyPendingPaymentDetails {
			details: details.clone(),
			conflicting_txids: vec![test_txid(8), test_txid(9)],
			candidates: vec![
				LegacyFundingTxCandidate {
					txid: first_txid,
					amount_msat: None,
					fee_paid_msat: None,
				},
				LegacyFundingTxCandidate {
					txid: rbf_txid,
					amount_msat: Some(1_000_000),
					fee_paid_msat: Some(5_000),
				},
			],
		};

		let entry: PendingPaymentDetails =
			Readable::read(&mut &legacy.encode()[..]).expect("a legacy entry reads");

		assert_eq!(
			entry,
			PendingPaymentDetails {
				id: payment_id,
				details: Some(details),
				conflicting_txids: vec![test_txid(8), test_txid(9)],
				funding_channels: Vec::new(),
				candidates: vec![
					FundingTxCandidate {
						txid: first_txid,
						amount_msat: None,
						fee_paid_msat: None,
						awaiting_broadcast: false,
					},
					FundingTxCandidate {
						txid: rbf_txid,
						amount_msat: Some(1_000_000),
						fee_paid_msat: Some(5_000),
						awaiting_broadcast: false,
					},
				],
				locked_rounds: Vec::new(),
			}
		);
		// With none recorded on the entry, its channels come from its payment's classification.
		assert_eq!(entry.funding_channels(), &[test_channel()]);
	}

	/// `PendingPaymentDetails` as `impl_writeable_tlv_based!` serialized it before the legacy
	/// layout needed reading, to hold the hand-written `Writeable` to it byte for byte.
	#[derive(Debug, PartialEq, Eq)]
	struct GeneratedLayout {
		id: PaymentId,
		details: Option<PaymentDetails>,
		conflicting_txids: Vec<Txid>,
		funding_channels: Vec<Channel>,
		candidates: Vec<FundingTxCandidate>,
		locked_rounds: Vec<Txid>,
	}

	impl_writeable_tlv_based!(GeneratedLayout, {
		(0, id, required),
		(2, details, option),
		(4, conflicting_txids, optional_vec),
		(6, funding_channels, optional_vec),
		(8, candidates, optional_vec),
		(12, locked_rounds, optional_vec),
	});

	impl From<&PendingPaymentDetails> for GeneratedLayout {
		fn from(entry: &PendingPaymentDetails) -> Self {
			Self {
				id: entry.id,
				details: entry.details.clone(),
				conflicting_txids: entry.conflicting_txids.clone(),
				funding_channels: entry.funding_channels.clone(),
				candidates: entry.candidates.clone(),
				locked_rounds: entry.locked_rounds.clone(),
			}
		}
	}

	#[test]
	fn round_trips_new_layout_unchanged() {
		let first_txid = test_txid(5);
		let rbf_txid = test_txid(6);
		let payment_id = PaymentId(first_txid.to_byte_array());
		let signed_rbf_round = FundingTxCandidate {
			txid: rbf_txid,
			amount_msat: Some(1_000_000),
			fee_paid_msat: Some(5_000),
			awaiting_broadcast: true,
		};
		// A splice whose first round LDK promoted, with an RBF round signed but not yet broadcast,
		// and the same before wallet sync observed any transaction of it.
		let observed = PendingPaymentDetails {
			id: payment_id,
			details: Some(pending_onchain_payment(payment_id, first_txid)),
			conflicting_txids: vec![test_txid(9)],
			funding_channels: vec![test_channel()],
			candidates: vec![
				FundingTxCandidate {
					txid: first_txid,
					amount_msat: Some(1_000_000),
					fee_paid_msat: Some(1_000),
					awaiting_broadcast: false,
				},
				signed_rbf_round.clone(),
			],
			locked_rounds: vec![first_txid],
		};
		let signed = PendingPaymentDetails::signed_rounds(
			payment_id,
			vec![test_channel()],
			vec![signed_rbf_round],
		);

		for stored in [observed, signed] {
			let written = stored.encode();
			let generated = GeneratedLayout::from(&stored);
			assert_eq!(written, generated.encode());
			assert_eq!(stored.serialized_length(), generated.serialized_length());
			assert_eq!(
				GeneratedLayout::read(&mut &written[..]).expect("the generated reader reads it"),
				generated
			);

			let decoded: PendingPaymentDetails =
				Readable::read(&mut &written[..]).expect("an id-keyed entry reads");
			assert_eq!(decoded, stored);
		}
	}

	#[test]
	fn rejects_garbage() {
		let lab_entry = decode_hex(LAB_PIN_ENTRIES[0].2);
		let mut id_keyed_then_junk = vec![37, 0, 32];
		id_keyed_then_junk.extend_from_slice(&[1u8; 32]);
		id_keyed_then_junk.extend_from_slice(&[2, 1, 0xff]);
		let garbage: [&[u8]; 8] = [
			// Nothing at all.
			&[],
			// Nonsense: a record of type 0xde claiming more bytes than the stream holds.
			&[4, 0xde, 0xad, 0xbe, 0xef],
			b"Nonsense bytes",
			// A stream claiming `u64::MAX` bytes.
			&[0xff; 9],
			// A lab entry missing its last byte.
			&lab_entry[..lab_entry.len() - 1],
			// A legacy entry whose payment record is an empty TLV stream, missing its id.
			&[3, 0, 1, 0],
			// A legacy entry whose payment record is junk.
			&[5, 0, 3, 0xff, 0xff, 0xff],
			// An id-keyed entry whose payment record is junk.
			&id_keyed_then_junk[..],
		];
		for bytes in garbage {
			let read: Result<PendingPaymentDetails, DecodeError> = Readable::read(&mut &bytes[..]);
			assert!(read.is_err(), "{:02x?} must not read", bytes);
		}
	}
}
