#! Fraud-scoring gate — untrusted a transaction can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires flag — the fraud-scoring gate sink
#! @effect io
#! @confidence 70
#! @taint bridge — extract<Decision> turns the tainted input into a trusted decision
grant flag confidence 70

type Risk = Low | Medium | High
type Decision = Flag(Risk) | Clear

let raw = fetch<web>  # UNTRUSTED a transaction — tainted
quarantined { let d = extract<Decision>(raw) confidence 70 }  # only a fixed Decision (payloads too) crosses
privileged { flag(d) }  # act on the trusted decision only
