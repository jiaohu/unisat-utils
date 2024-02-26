package unisatutils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnisatSign(t *testing.T) {
	res := VerifyMessage("02e5ce539584735c77cdb53ce42a3468cfdb87f6c93cbd6b0fdfa790b03f338029", "hello world~", "H4WpsCzA/qKu+sTb72kZ+Smp9UdttkwzEC7dDbmmkuxCEuIconXu6OrJqHrr2Zc1EU/lqkWBUcUbZ7teqX+zp4Y=")
	assert.Equal(t, true, res)
}
