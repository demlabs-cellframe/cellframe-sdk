# Setup arbitres consensus count
OP_${arbitr-count-consensus}
# List arbitrs public keys
{{for: i from 0 to ${arbitr-count} }}
{{arbitr-${i}.public_key}}
{{endfor}}
# Check multisig if they are
OP_${arbitr-count}
OP_CHECKMULTISIG
OP_IF
OP_VERIFY
OP_ELSE
# Here is the verificators check
OP_ENDIF
