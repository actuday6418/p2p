#[macro_use]
extern crate magic_crypt;
extern crate serde;
extern crate serde_json;

use magic_crypt::MagicCryptTrait;
use serde::{Deserialize, Serialize};
use std::net::UdpSocket;
use std::sync::mpsc;
use std::thread;

#[derive(Serialize, Deserialize)]
struct Packet {
    adv_name: String, //Advertised name
    msg: String,      //Message
}

fn send(saddr: &str, name: String, msg: String, toaddr: &str) {
    let data = &(r#"{
       "adv_name": ""#
        .to_owned()
        + &name
        + &r#"",
       "msg": ""#
            .to_owned()
        + &msg
        + &r#""
        }"#
        .to_owned());

    let sock = UdpSocket::bind(saddr).expect("Couldn't bind sender");

    //encryption key
    let mc = new_magic_crypt!("key", 256);
    let bytes = mc.encrypt_str_to_bytes(data);

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

fn recieve(laddr: &str) {
    let mc = new_magic_crypt!("key", 256);

    //used to sync between threads
    let (tx, rx) = mpsc::channel();

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
                    if buff == [0u8; 64] {
                        let copied_buff = data.clone();
                        tx.send(copied_buff).unwrap();
                        println!("Clearing..");
                        data.clear();
                    } else {
                        data.extend_from_slice(&buff[0..amt]);
                    }
                }
                Err(e) => println!("Couldn't recieve: {}", e),
            }
        }
    });

    //wait for messages from the new thread
    loop {
        let recieved = rx.try_recv();
        if recieved.is_ok() {
            let recieved = recieved.unwrap();
            let recieved = mc.decrypt_bytes_to_bytes(&recieved).unwrap();
            let recieved = std::str::from_utf8(&recieved).unwrap();
            let recieved: Packet = serde_json::from_str(recieved).unwrap();
            println!("msg: {} from: {}", recieved.msg, recieved.adv_name);
        }
    }
}

fn handle_send() {
    let mut name: String = String::from("Nolan");
    let mut msg: String = String::from("Hello!");
    let mut saddr = String::new();
    let mut taddr = String::new();

    println!("Enter the sender's address: ");
    std::io::stdin().read_line(&mut saddr).unwrap();
    let saddr = saddr.trim();

    println!("Enter the target's address: ");
    std::io::stdin().read_line(&mut taddr).unwrap();
    let taddr = taddr.trim();

    println!("Enter the sender's name: ");
    std::io::stdin().read_line(&mut name).unwrap();
    let name = name.trim().to_string();

    println!("Enter the message: ");
    std::io::stdin().read_line(&mut msg).unwrap();
    let msg = msg.trim().to_string();

    let taddr = taddr.trim();
    send(saddr, name, msg, taddr);
}

fn handle_recieve() {
    //reciever and sender addresses
    let mut laddr = String::new();

    println!("Enter the listener's address: ");
    std::io::stdin().read_line(&mut laddr).unwrap();
    let laddr = laddr.trim();

    recieve(laddr);
}

fn main() {
    println!("Enter your choice:\n1) Listen (Blocking)\n2) Send\n3) Exit");
    let mut stri = String::new();
    std::io::stdin().read_line(&mut stri).unwrap();
    match stri.trim() {
        "1" => handle_recieve(),
        "2" => handle_send(),
        _ => (),
    }
}
