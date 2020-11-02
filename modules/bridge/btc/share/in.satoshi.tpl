{{for: i from 0 to $arbitr-count }}
OP_IF
  <arbitr-{i}.public_key>
  OP_CHECKSIGVERIFY
  <1>
OP_ELSE
  <2>
OP_ENDIF
{{endfor}}
