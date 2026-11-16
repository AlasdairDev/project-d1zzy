# User security guide

D1zzy is built to reduce what the server can see, but it cannot protect you from a lost
passphrase, a phishing clone or a scammer. This page is the short version.

This is the version I would give a friend before they used the site. It is not a guarantee,
and it will not save you from a bad decision, but it covers the things that actually go wrong.

## 1. Check the address

- Prefer the `.onion` address from a source you trust. Onion names are long and easy to
  mistype.
- If you reach the site over HTTPS, look for the `Onion-Location` header or the onion link
  in the footer, then compare it character by character.
- A clone can look identical. The address is the only reliable signal.

## 2. Protect your passphrase

- Use a long, unique passphrase. It is stretched with Argon2id in your browser, not stored
  on the server.
- If you lose it, you lose your identity and your message history. There is no recovery.
- Do not paste it into a chat, a support form or another site.

## 3. Compare safety numbers

Open a conversation, expand **Verify this chat**, and read the digits to the other person
over a call or in person. If the numbers match, the server has not swapped a key. If they do
not match, stop and investigate. Do not send sensitive messages until they match.

## 4. Know what the server can see

| Mode | What the server sees |
|------|----------------------|
| Listings, offers, ratings | Sealed at rest, but public by design. Anyone who can reach the site can read them |
| Chat with JavaScript and keys | Ciphertext only. The server relays bytes it cannot read |
| Chat without JavaScript or keys | Plaintext, encrypted at rest, marked "not end-to-end encrypted" |
| Reported messages | The reported message is disclosed to moderators |
| Payment | The provider sees your email and the amount. Card data never reaches the server |

## 5. Common scams

- **Off-platform payment.** A seller asks you to pay by bank transfer or a gift card. You
  lose the marketplace's weak protection and any payment dispute path.
- **Fake payment proof.** A buyer sends a screenshot instead of a provider confirmation.
  Check the offer status, not the screenshot.
- **Overpayment.** A buyer "accidentally" sends too much and asks for a refund. The original
  payment is often reversed later.
- **Phishing clone.** A link in a message points to a lookalike onion address.
- **Fake support.** Nobody from D1zzy will ask for your passphrase, keys or a payment.

## 6. Safer trading

- Keep the conversation on the platform, even if it is slower.
- Use a payment method with a dispute process when you can.
- Check the seller's rating and how long the account has existed, but do not treat either as
  proof.
- Meet in a public place for physical goods.
- Report anything that feels wrong. Reports create an audit record.

## 7. Protect your device

- Keep the browser and operating system updated.
- Use a device you control. Shared computers can retain history, downloads and clipboard
  contents.
- Close the browser when you are done. Ratchet state lives in memory.

## 8. Report a problem

- Use the report button on the listing, message or profile.
- For a vulnerability, follow `.github/SECURITY.md`. Do not open a public issue.
- For a safety emergency, contact local authorities first. This project does not have a
  24/7 response team.
