package ledgerguard

// Control is one regulatory or industry control a finding maps to.
// Mappings are indicative and framed at clause/requirement level; a bank's
// compliance team owns the final attestation.
type Control struct {
	Framework string `json:"framework"`
	Ref       string `json:"ref"`
	Title     string `json:"title"`
}

var (
	ctlPCI624   = Control{"PCI DSS v4.0", "6.2.4", "Software engineering techniques prevent common attacks, including business-logic abuse via API manipulation"}
	ctlPCI834   = Control{"PCI DSS v4.0", "8.3.4", "Invalid authentication attempts are limited (lockout after not more than 10 attempts)"}
	ctlPCI72    = Control{"PCI DSS v4.0", "7.2", "Access to system components and data is appropriately defined and assigned"}
	ctlRBIDPSC  = Control{"RBI", "Master Direction on Digital Payment Security Controls (2021)", "Application security, transaction integrity and authentication controls for digital payment products"}
	ctlRBIITGov = Control{"RBI", "Master Direction on IT Governance, Risk, Controls & Assurance (2023)", "Application controls for data integrity, reconciliation and audit trails"}
	ctlRBICSF   = Control{"RBI", "Cyber Security Framework for Banks (2016)", "Baseline application security and access controls"}
	ctlDPDP85   = Control{"DPDP Act 2023", "Sec 8(5)", "Reasonable security safeguards to prevent personal data breach"}
	ctlOWASP1   = Control{"OWASP API Top 10 (2023)", "API1", "Broken Object Level Authorization"}
	ctlOWASP2   = Control{"OWASP API Top 10 (2023)", "API2", "Broken Authentication"}
	ctlOWASP6   = Control{"OWASP API Top 10 (2023)", "API6", "Unrestricted Access to Sensitive Business Flows"}
)

func controlsFor(inv string) []Control {
	switch inv {
	case InvConservation:
		return []Control{ctlPCI624, ctlRBIITGov, ctlRBIDPSC, ctlOWASP6}
	case InvNonNegative, InvIdempotency:
		return []Control{ctlPCI624, ctlRBIDPSC, ctlRBIITGov, ctlOWASP6}
	case InvAuthority:
		return []Control{ctlOWASP1, ctlPCI72, ctlRBICSF, ctlDPDP85}
	case InvStepUpCeil:
		return []Control{ctlPCI834, ctlRBIDPSC, ctlOWASP2}
	}
	return nil
}
