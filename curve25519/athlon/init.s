.text
.p2align 5
.globl _crypto_smult_curve25519_athlon_init
.globl crypto_smult_curve25519_athlon_init
_crypto_smult_curve25519_athlon_init:
crypto_smult_curve25519_athlon_init:
mov %esp,%eax
and $31,%eax
add $0,%eax
sub %eax,%esp
fldcw crypto_smult_curve25519_athlon_rounding
add %eax,%esp
ret
