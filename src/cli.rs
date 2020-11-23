#[macro_use]
extern crate magic_crypt;
extern crate serde;
extern crate serde_json;

use magic_crypt::MagicCryptTrait;
use serde::{Deserialize, Serialize};
use std::net::UdpSocket;
use std::thread;
use std::sync::mpsc;

#[derive(Serialize, Deserialize)]
struct Packet {
    adv_name: String, //Advertised name
    msg: String,      //Message
}

fn send(sock: UdpSocket, bytes: Vec<u8>, toaddr: &str) {
    let len = bytes.len();
    let mut i = 0;
    loop {
        if i + 64 > len {
            if len % 64 == 0 {
                break;
            } else {
                sock.send_to(&bytes[i..len], toaddr).unwrap();
                break;
            }
        }
        sock.send_to(&bytes[i..i + 64], toaddr).unwrap();
        i += 64;
    }
    sock.send_to(&[0; 64], toaddr).unwrap();
}

fn main() {

    //used to sync between threads
    let (tx, rx) = mpsc::channel();

    let data = r#"{
    "adv_name": "My name is Nolan and Nolan is my name and there is no other name but Nolan!",
    "msg": "Hello there!"
    }"#;

    //reciever and sender addresses
    let mut laddr = String::new();
    let mut saddr = String::new();

    println!("Enter the listener's address: ");
    std::io::stdin().read_line(&mut laddr).unwrap();
    println!("Enter the sender's address: ");
    std::io::stdin().read_line(&mut saddr).unwrap();
    let saddr = saddr.trim();
    let laddr = laddr.trim();

    //variable is captured by closure
    let lost_listener_addr = laddr.clone().to_owned();

    //spawn listener
    thread::spawn(move || {
        let lsock = UdpSocket::bind(lost_listener_addr).expect("Couldn't bind listener");
        let mut buff = [0; 64];
        let mut data: Vec<u8> = Vec::new();
        loop {
            match lsock.recv_from(&mut buff) {
                Ok((amt, _)) => {
                    println!("Recieved packet of size: {}", amt);
                    if buff == [0;64] {
                        let copied_buff = data.clone();
                        tx.send(copied_buff).unwrap();
                        println!("Clearing..");
                        data.clear();
                    } else {
                        data.extend_from_slice( &buff[0 .. amt]);
                    }
                },
                Err(e) => println!("Couldn't recieve: {}", e),
            }
        }
    });

    let sock = UdpSocket::bind(saddr).expect("Couldn't bind sender");

    //encryption key
    let mc = new_magic_crypt!("key", 256);

    let e = mc.encrypt_str_to_bytes(data);

    //let ans = std::str::from_utf8(&ans).unwrap();

    send(sock, e, laddr);
    //let stru: Message = serde_json::from_str(ans).unwrap();
    loop{
        let recieved = rx.try_recv();
        if recieved.is_ok() {
            let recieved = recieved.unwrap();
            let recieved = mc.decrypt_bytes_to_bytes(&recieved).unwrap();
            let recieved = std::str::from_utf8(&recieved).unwrap();
            let recieved: Packet = serde_json::from_str(recieved).unwrap();
            println!("name: {}", recieved.adv_name);
        } 
    }
}
