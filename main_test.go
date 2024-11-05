package main

import (
    "testing"
)

func TestSendCode(t *testing.T) {
    phoneNumber := "6176526877" // Replace with a valid phone number
    phoneCarrier := "T-Mobile"    // Replace with a supported carrier

    verificationCode, err := SendCode(phoneNumber, phoneCarrier)
    if err != nil {
        t.Fatalf("Error sending code: %v", err)
    }

    t.Logf("Verification code sent: %d\n", verificationCode)
}
