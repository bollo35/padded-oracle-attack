An implementation of a server providing a padded oracle as well as a client to implement a padded oracle attack.

## Info
The padding scheme used for encryption of the secret message is PKCS#7 and the block size for the cipher is 16 bytes.
The server listens on port 5000 and expects a message of the following format:
```
[message length][message]
```
`message length` is a byte long and does not include the byte used for `message length` (i.e. it is the number of bytes for `message`, so `3abc` is an acceptable message)

The server will respond with a single byte (ASCII encoded character) after receiving a message:
- `y` to indicate the ciphertext is valid.
- `n` to indicate the ciphertext is invalid.

To shutdown the server, simply send the following 5 byte message (ascii encoding for the letters):
`4exit`


The secret message is located in `msg.txt` and has the following format:
```
[iv][ciphertext]
```

`solutions/Rust/attack.rs` is a solution to the problem.

If you want to submit a different solution or improve upon mine feel free to submit a pull request.
