use std::net::TcpStream;
use std::io::Write;
use std::fs::File;
use std::io::Read;
use std::error::Error;
use std::convert::AsMut;

fn clone_into_array<A, T>(slice: &[T]) -> A
		where A: Sized + Default + AsMut<[T]>,
		      T: Clone
{
	let mut a = Default::default();
	<A as AsMut<[T]>>::as_mut(&mut a).clone_from_slice(slice);
	a
}

pub struct CommChannel {
	stream: TcpStream,
}

impl CommChannel {
	pub fn new() -> Result<CommChannel, Box<Error>> {
		let stream = try!(TcpStream::connect("127.0.0.1:5000"));
		Result::Ok(CommChannel { stream: stream })
	}

	pub fn is_msg_valid(&mut self, iv: &[u8], block: &[u8]) -> Result<bool, Box<Error>> {
		let msg_len = BLOCK_SIZE * 2;
		let mut msg : Vec<u8> = Vec::with_capacity(msg_len);
		msg.push(msg_len as u8);
		msg.extend_from_slice(iv);
		msg.extend_from_slice(block);
		
		try!(self.stream.write(&msg[..]));

		// read server response
		let mut buf = [0; 1];
		try!(self.stream.read(&mut buf));
		Result::Ok(buf[0] as char == 'y')
	}


	pub fn disconnect(&mut self) {
		let _ = self.stream.write(&[4, 'e' as u8, 'x' as u8, 'i' as u8, 't' as u8]);
	}
}

const BLOCK_SIZE: usize = 16;

fn main() {
	let mut comm = CommChannel::new().unwrap();
	let open_result = File::open("msg.txt");
	if open_result.is_ok() {
		// load message for decryption from file
		let mut msg_file = open_result.unwrap();
		let mut msg = String::new();
		let _ = msg_file.read_to_string(&mut msg);

		// convert message to a Vec or bytes
		let bytes = hex_to_bytes(&msg);

		let mut decryption : Vec<u8> = Vec::with_capacity(bytes.len());
		let chunked = bytes.as_slice().chunks(BLOCK_SIZE);
		for (iv, block) in chunked.clone().zip(chunked.skip(1)) {
			let iv_prime = process_block(&mut comm, &iv, &block);
			let mut dec : Vec<u8>= iv.iter().zip(iv_prime.iter()).map(|(a,b)| (a ^ b ^ 16u8)).collect();
			decryption.append(&mut dec);
		}

		let padding = decryption.last().unwrap().clone() as usize;
		let len = decryption.len();
		decryption.truncate(len - padding);
		let decryption = String::from_utf8(decryption).unwrap();
		println!("Original Message: {}", decryption);
		comm.disconnect();
	}
}

fn process_block(comm: &mut CommChannel, iv: &[u8], block: &[u8]) -> [u8; 16] {
	let mut scratch_iv :[u8; 16] = clone_into_array(iv);
	let mut mask : [u8; 16] = [0u8; 16];

	for byte in 0..BLOCK_SIZE {
		let index = BLOCK_SIZE - byte - 1;
		// we want this padding value to be valid
		let pad = (byte + 1) as u8;
		let range = (BLOCK_SIZE - byte)..BLOCK_SIZE;
		for (i, mut siv) in range.clone().zip(scratch_iv[range].iter_mut()) {
			let pad_size = (BLOCK_SIZE - i) as u8;
			// IV' = IV xor Value Xored to get pad of length pad_size xor pad_size (to remove it) xor pad (the padding length that we actually want)
			*siv = iv[i] ^ mask[i] ^ pad_size ^ pad;
		}
		for i in 0..255 {
			// index of the byte we're fiddling with
			scratch_iv[index] = iv[index] ^ i;
			let valid = comm.is_msg_valid(&scratch_iv, &block).unwrap();
			if valid {
				mask[index] = i;
			}
		}
	}
	scratch_iv[0] = mask[0] ^ iv[0];
	scratch_iv
}

fn hex_to_bytes(hex_str: &str) -> Vec<u8> {
	hex_str.chars().map(|c|  c.to_digit(16).unwrap() as u8).collect::<Vec<u8>>().chunks(2).map(|i| i[0] << 4 | i[1]).collect::<Vec<u8>>()
}
