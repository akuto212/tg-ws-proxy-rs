use cipher::{KeyIvInit, StreamCipher};

type Aes256Ctr = ctr::Ctr64BE<aes::Aes256>;

const PROTO_ABRIDGED: u32 = 0xEFEFEFEF;
const PROTO_INTERMEDIATE: u32 = 0xEEEEEEEE;
const PROTO_PADDED_INTERMEDIATE: u32 = 0xDDDDDDDD;

pub struct MsgSplitter {
    cipher: Aes256Ctr,
    proto: u32,
    remaining: usize,
}

impl MsgSplitter {
    /// Create from relay_init's key (bytes 8..40) and IV (bytes 40..56).
    /// `proto_int` is one of PROTO_ABRIDGED / PROTO_INTERMEDIATE / PROTO_PADDED_INTERMEDIATE.
    pub fn new(key: &[u8], iv: &[u8], proto_int: u32) -> Self {
        let mut cipher = Aes256Ctr::new(key.into(), iv.into());
        let mut skip = [0u8; 64];
        cipher.apply_keystream(&mut skip);
        Self {
            cipher,
            proto: proto_int,
            remaining: 0,
        }
    }

    /// Returns byte offsets in `ciphertext` where each complete message ends.
    pub fn split(&mut self, ciphertext: &[u8]) -> Vec<usize> {
        let mut plaintext = ciphertext.to_vec();
        self.cipher.apply_keystream(&mut plaintext);

        let mut boundaries = Vec::new();
        let mut pos = 0;

        while pos < plaintext.len() {
            if self.remaining > 0 {
                let consume = self.remaining.min(plaintext.len() - pos);
                self.remaining -= consume;
                pos += consume;
                if self.remaining == 0 {
                    boundaries.push(pos);
                }
                continue;
            }

            match self.next_packet_len(&plaintext[pos..]) {
                Some(0) => break,
                None => break,
                Some(packet_len) => {
                    let available = plaintext.len() - pos;
                    if packet_len <= available {
                        pos += packet_len;
                        boundaries.push(pos);
                    } else {
                        self.remaining = packet_len - available;
                        pos = plaintext.len();
                    }
                }
            }
        }

        boundaries
    }

    fn next_packet_len(&self, plain: &[u8]) -> Option<usize> {
        if plain.is_empty() {
            return None;
        }
        if self.proto == PROTO_ABRIDGED {
            self.next_abridged_len(plain)
        } else if self.proto == PROTO_INTERMEDIATE || self.proto == PROTO_PADDED_INTERMEDIATE {
            self.next_intermediate_len(plain)
        } else {
            Some(0)
        }
    }

    fn next_abridged_len(&self, plain: &[u8]) -> Option<usize> {
        let first = plain[0];
        if first == 0 {
            return Some(0);
        }

        if first >= 0x7f {
            if plain.len() < 4 {
                return None;
            }
            let len = (plain[1] as usize)
                | ((plain[2] as usize) << 8)
                | ((plain[3] as usize) << 16);
            let payload = len * 4;
            if payload == 0 {
                return Some(0);
            }
            Some(4 + payload)
        } else {
            let payload = (first & 0x7F) as usize * 4;
            if payload == 0 {
                return Some(0);
            }
            Some(1 + payload)
        }
    }

    fn next_intermediate_len(&self, plain: &[u8]) -> Option<usize> {
        if plain.len() < 4 {
            return None;
        }
        let payload_len = (u32::from_le_bytes([plain[0], plain[1], plain[2], plain[3]]) & 0x7FFFFFFF) as usize;
        if payload_len == 0 {
            return Some(0);
        }
        Some(4 + payload_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encrypt_with_offset(plaintext: &[u8]) -> Vec<u8> {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        let mut cipher = Aes256Ctr::new((&key).into(), (&iv).into());
        let mut skip = [0u8; 64];
        cipher.apply_keystream(&mut skip);
        let mut ct = plaintext.to_vec();
        cipher.apply_keystream(&mut ct);
        ct
    }

    fn make_splitter(proto: u32) -> MsgSplitter {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        MsgSplitter::new(&key, &iv, proto)
    }

    #[test]
    fn test_abridged_single_message() {
        let mut plaintext = vec![0u8; 9];
        plaintext[0] = 2; // 2*4=8 payload, total=1+8=9
        let ct = encrypt_with_offset(&plaintext);
        let mut splitter = make_splitter(PROTO_ABRIDGED);
        assert_eq!(splitter.split(&ct), vec![9]);
    }

    #[test]
    fn test_abridged_two_messages() {
        let mut plaintext = vec![0u8; 14];
        plaintext[0] = 1; // 4 bytes payload, total=5
        plaintext[5] = 2; // 8 bytes payload, total=9
        let ct = encrypt_with_offset(&plaintext);
        let mut splitter = make_splitter(PROTO_ABRIDGED);
        assert_eq!(splitter.split(&ct), vec![5, 14]);
    }

    #[test]
    fn test_abridged_partial_across_chunks() {
        let mut plaintext = vec![0u8; 13];
        plaintext[0] = 3; // 12 payload, total=13
        let full_ct = encrypt_with_offset(&plaintext);
        let mut splitter = make_splitter(PROTO_ABRIDGED);
        assert_eq!(splitter.split(&full_ct[..6]), vec![]);
        assert_eq!(splitter.split(&full_ct[6..]), vec![7]); // 13-6=7
    }

    #[test]
    fn test_intermediate_single_message() {
        let payload_len: u32 = 16;
        let total = 4 + payload_len as usize;
        let mut plaintext = vec![0u8; total];
        plaintext[..4].copy_from_slice(&payload_len.to_le_bytes());
        let ct = encrypt_with_offset(&plaintext);
        let mut splitter = make_splitter(PROTO_INTERMEDIATE);
        assert_eq!(splitter.split(&ct), vec![total]);
    }

    #[test]
    fn test_intermediate_two_messages() {
        let len1: u32 = 8;
        let len2: u32 = 12;
        let total = (4 + len1 + 4 + len2) as usize;
        let mut plaintext = vec![0u8; total];
        plaintext[..4].copy_from_slice(&len1.to_le_bytes());
        plaintext[(4 + len1 as usize)..][..4].copy_from_slice(&len2.to_le_bytes());
        let ct = encrypt_with_offset(&plaintext);
        let mut splitter = make_splitter(PROTO_INTERMEDIATE);
        assert_eq!(splitter.split(&ct), vec![12, total]);
    }

    #[test]
    fn test_padded_intermediate_uses_same_framing() {
        let payload_len: u32 = 16;
        let total = 4 + payload_len as usize;
        let mut plaintext = vec![0u8; total];
        plaintext[..4].copy_from_slice(&payload_len.to_le_bytes());
        let ct = encrypt_with_offset(&plaintext);
        let mut splitter = make_splitter(PROTO_PADDED_INTERMEDIATE);
        assert_eq!(splitter.split(&ct), vec![total]);
    }
}
