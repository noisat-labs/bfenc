extern crate rand;
extern crate sha3;
extern crate digest;
extern crate byteorder;
extern crate pairing;
extern crate ibbe;

use rand::Rng;
use sha3::{ Shake256, Sha3XofReader };
use digest::{ Input, ExtendableOutput, XofReader };
use byteorder::{ ByteOrder, LittleEndian };
use pairing::bls12_381::Fq12;


pub const K: usize = 3;
pub const M: usize = 128;

pub type Gt = Fq12;

pub struct Pk(ibbe::Mpk);
pub struct Sk(Vec<Option<ibbe::Sk>>);
pub struct Ct(ibbe::Hdr);


pub fn keypair<R: Rng>(rng: &mut R) -> (Pk, Sk) {
    let (msk, mpk) = ibbe::setup(rng);

    let sk = (0..M)
        .map(|i| Some(ibbe::keygen(rng, &mpk, &msk, i.to_string().as_str())))
        .collect::<Vec<_>>();

    (Pk(mpk), Sk(sk))
}

pub fn enc<R: Rng>(rng: &mut R, Pk(pk): &Pk, tag: &str) -> (Gt, Ct) {
    let ids = hash(tag);
    let ids = ids.iter().map(|&i| i.to_string());

    let (k, hdr) = ibbe::enc(rng, pk, ids);
    (k, Ct(hdr))
}

pub fn dec(Sk(sks): &Sk, Ct(hdr): &Ct, tag: &str) -> Option<Gt> {
    let ids = hash(tag);

    let (i, sk) = ids.iter()
        .cloned()
        .find_map(|i| sks.get(i)
            .and_then(|sk| sk.clone())
            .map(|sk| (i, sk))
        )?;

    ibbe::dec(
        &sk,
        hdr,
        i.to_string().as_str(),
        ids.iter().map(|i| i.to_string())
    )
}

pub fn puncture(Sk(sks): &mut Sk, tag: &str) {
    for &i in &hash(tag) {
        sks[i] = None;
    }
}


fn hash(tag: &str) -> [usize; K] {
    struct HashRng(Sha3XofReader);

    impl HashRng {
        fn new<A: AsRef<[u8]>>(k: u32, value: A) -> HashRng {
            let mut hasher = Shake256::default();
            let mut buf = [0; 4];
            LittleEndian::write_u32(&mut buf, k);
            hasher.process(&buf);
            hasher.process(value.as_ref());
            HashRng(hasher.xof_result())
        }
    }

    impl Rng for HashRng {
        fn next_u32(&mut self) -> u32 {
            let mut bytes = [0; 4];
            self.fill_bytes(&mut bytes);
            LittleEndian::read_u32(&bytes)
        }

        fn next_u64(&mut self) -> u64 {
            let mut bytes = [0; 8];
            self.fill_bytes(&mut bytes);
            LittleEndian::read_u64(&bytes)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.0.read(dest)
        }
    }

    let mut output = [0; K];
    for i in 0..K {
        let mut rng = HashRng::new(i as u32, tag);
        loop {
            let n = rng.gen::<usize>() % M;
            if output[..i].iter().any(|&x| x == n) {
                continue
            } else {
                output[i] = n;
                break
            }
        }
    }
    output
}


#[test]
fn test_bfenc() {
    use rand::thread_rng;

    let mut rng = thread_rng();
    let tag1 = "Hello";
    let tag2 = "World";

    let (pk, mut sk) = keypair(&mut rng);
    let (k, ct) = enc(&mut rng, &pk, tag1);
    let k2 = dec(&sk, &ct, tag1).unwrap();
    assert_eq!(k, k2);

    puncture(&mut sk, tag1);
    assert!(dec(&sk, &ct, tag1).is_none());

    let (k, ct) = enc(&mut rng, &pk, tag2);
    let k2 = dec(&sk, &ct, tag2).unwrap();
    assert_eq!(k, k2);
}
