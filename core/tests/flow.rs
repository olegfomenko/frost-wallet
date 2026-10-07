//! Drives complete sessions through the JSON API, the way the page does:
//! one coordinator wallet and `n` participant wallets exchanging text blobs.

use frost_wallet_core::wallet::Wallet;
use serde_json::{Value, json};

fn wallet(role: &str) -> Wallet {
    let mut w = Wallet::new(Box::new(|buf: &mut [u8]| {
        getrandom::getrandom(buf).unwrap()
    }));
    call(&mut w, json!({ "op": "set_role", "role": role }));
    w
}

fn try_call(w: &mut Wallet, req: Value) -> Result<Value, String> {
    let resp: Value = serde_json::from_str(&w.handle(&req.to_string())).unwrap();
    if resp["ok"] == true {
        Ok(resp)
    } else {
        Err(resp["error"].as_str().unwrap().to_string())
    }
}

fn call(w: &mut Wallet, req: Value) -> Value {
    try_call(w, req).unwrap()
}

fn import(w: &mut Wallet, data: &Value) -> Value {
    call(w, json!({ "op": "import", "data": data.as_str().unwrap() }))
}

fn state(w: &mut Wallet) -> Value {
    call(w, json!({ "op": "state" }))["state"].clone()
}

struct Group {
    coordinator: Wallet,
    participants: Vec<Wallet>,
}

fn keygen(n: usize, t: usize) -> Group {
    let mut c = wallet("coordinator");
    let mut ps: Vec<Wallet> = (0..n).map(|_| wallet("participant")).collect();

    for p in &mut ps {
        let s = call(p, json!({ "op": "p_new_host" }));
        let r = import(&mut c, &s["state"]["host"]["out"]["data"]);
        assert_eq!(r["result"]["more"], true);
    }
    let s = call(&mut c, json!({ "op": "c_dkg_start", "t": t }));
    let params = s["state"]["dkg"]["params"]["data"].clone();

    let mut c1 = Value::Null;
    for (i, p) in ps.iter_mut().enumerate() {
        let s = import(p, &params);
        assert_eq!(s["state"]["dkg"]["stage"], "review");
        assert_eq!(s["state"]["dkg"]["idx"], i);
        let s = call(p, json!({ "op": "p_dkg_join" }));
        let r = import(&mut c, &s["state"]["dkg"]["out"]["data"]);
        assert_eq!(r["result"]["more"], i + 1 < n);
        c1 = r["state"]["dkg"]["out1"]["data"].clone();
    }

    let mut c2 = Value::Null;
    for p in ps.iter_mut() {
        let s = import(p, &c1);
        assert_eq!(s["state"]["dkg"]["stage"], "round2");
        // A replayed coordinator message must not burn the session.
        assert!(try_call(p, json!({ "op": "import", "data": c1 })).is_err());
        assert_eq!(state(p)["dkg"]["stage"], "round2");
        let r = import(&mut c, &s["state"]["dkg"]["out"]["data"]);
        c2 = r["state"]["dkg"]["out2"]["data"].clone();
    }

    let group = state(&mut c)["group"].clone();
    assert_eq!(group["t"], t);
    assert_eq!(group["n"], n);
    for p in ps.iter_mut() {
        let s = import(p, &c2);
        assert_eq!(s["state"]["dkg"]["stage"], "done");
        assert_eq!(s["state"]["group"]["xonly"], group["xonly"]);
        assert_eq!(s["state"]["group"]["recovery"], group["recovery"]);
    }
    Group {
        coordinator: c,
        participants: ps,
    }
}

fn sign(g: &mut Group, signers: &[usize], msg: &[u8], tweaks: Value) -> Value {
    let c = &mut g.coordinator;
    let s = call(
        c,
        json!({ "op": "c_sign_start", "msg": hex::encode(msg), "tweaks": tweaks }),
    );
    let request = s["state"]["sign"]["request"]["data"].clone();

    for &i in signers {
        let p = &mut g.participants[i];
        let s = import(p, &request);
        assert_eq!(s["state"]["sign"]["stage"], "review");
        assert_eq!(s["state"]["sign"]["msg"]["hex"], hex::encode(msg));
        assert_eq!(s["state"]["sign"]["msg"]["len"], msg.len());
        let s = call(p, json!({ "op": "p_sign_approve" }));
        import(c, &s["state"]["sign"]["out"]["data"]);
    }
    let s = call(c, json!({ "op": "c_sign_package" }));
    let package = s["state"]["sign"]["package"]["data"].clone();

    let mut last = Value::Null;
    for &i in signers {
        let p = &mut g.participants[i];
        let s = import(p, &package);
        assert_eq!(s["state"]["sign"]["stage"], "done");
        last = import(c, &s["state"]["sign"]["out"]["data"]);
    }
    assert_eq!(last["state"]["sign"]["stage"], "done");
    last["state"]["sign"]["signature"].clone()
}

#[test]
fn keygen_and_sign_2_of_3() {
    let mut g = keygen(3, 2);
    let msg = b"hello offline world";
    let signature = sign(&mut g, &[0, 2], msg, json!([]));

    // An untweaked signature verifies under the group's x-only key.
    let group = state(&mut g.coordinator)["group"].clone();
    assert_eq!(signature["pubkey"], group["xonly"]);

    // Anyone can verify the exported signature blob, in any role.
    let mut outsider = wallet("participant");
    let r = import(&mut outsider, &signature["out"]["data"]);
    assert_eq!(r["state"]["verified"]["valid"], true);
    assert_eq!(r["state"]["verified"]["msg"]["text"], "hello offline world");
    assert_eq!(r["state"]["verified"]["ours"], false);

    // The signature covers SHA-256 of the message, never the raw bytes.
    {
        use chilldkg_rs::crypto::ec::decompress_default;
        use sha2::{Digest, Sha256};
        let mut key = [0u8; 33];
        key[0] = 0x02;
        hex::decode_to_slice(signature["pubkey"].as_str().unwrap(), &mut key[1..]).unwrap();
        let key = decompress_default(&key).unwrap();
        let mut sig = [0u8; 64];
        hex::decode_to_slice(signature["sig"].as_str().unwrap(), &mut sig).unwrap();
        chilldkg_rs::sign::verify(&key, sig, &Sha256::digest(msg), &[]).unwrap();
        assert!(chilldkg_rs::sign::verify(&key, sig, msg, &[]).is_err());
    }

    // Verification takes the raw message too; a different message must fail.
    let verify = |w: &mut Wallet, m: &[u8]| {
        call(
            w,
            json!({ "op": "verify", "pubkey": signature["pubkey"], "sig": signature["sig"], "msg": hex::encode(m) }),
        )["state"]["verified"]
            .clone()
    };
    let v = verify(&mut g.coordinator, msg);
    assert_eq!(
        (v["valid"].clone(), v["ours"].clone()),
        (json!(true), json!(true))
    );
    assert_eq!(
        verify(&mut g.coordinator, b"hello offline worle")["valid"],
        false
    );

    // The compressed form of the group key is accepted as well.
    let v = call(
        &mut g.coordinator,
        json!({ "op": "verify", "pubkey": group["pubkey"], "sig": signature["sig"], "msg": hex::encode(msg) }),
    );
    assert_eq!(v["state"]["verified"]["valid"], true);
}

#[test]
fn sign_with_tweaks_and_all_signers() {
    let mut g = keygen(2, 2);
    let tweaks = json!([
        { "value": "11".repeat(32), "xonly": false },
        { "value": "22".repeat(32), "xonly": true },
    ]);
    let msg = [0xabu8; 32];
    let signature = sign(&mut g, &[0, 1], &msg, tweaks);
    let group = state(&mut g.coordinator)["group"].clone();
    assert_ne!(signature["pubkey"], group["xonly"]);
    let v = call(
        &mut g.coordinator,
        json!({ "op": "verify", "pubkey": signature["pubkey"], "sig": signature["sig"], "msg": hex::encode(msg) }),
    );
    assert_eq!(v["state"]["verified"]["valid"], true);
}

#[test]
fn backups_restore_the_same_share() {
    let mut g = keygen(3, 2);
    let p = &mut g.participants[1];
    let before = state(p);
    let host = call(p, json!({ "op": "export", "what": "host_secret" }))["result"]["data"].clone();
    let share = call(p, json!({ "op": "export", "what": "share" }))["result"]["data"].clone();
    let recovery = before["group"]["recovery"]["data"].clone();

    // Host secret key + recovery data.
    let mut a = wallet("participant");
    assert!(try_call(&mut a, json!({ "op": "import", "data": recovery })).is_err());
    import(&mut a, &host);
    let s = import(&mut a, &recovery);
    assert_eq!(s["state"]["group"], before["group"]);
    assert_eq!(
        call(&mut a, json!({ "op": "export", "what": "share" }))["result"]["data"],
        share
    );

    // Share backup alone; recovery data can be attached afterwards.
    let mut b = wallet("participant");
    let s = import(&mut b, &share);
    assert_eq!(s["state"]["group"]["xonly"], before["group"]["xonly"]);
    assert_eq!(s["state"]["group"]["recovery"], Value::Null);
    let s = import(&mut b, &recovery);
    assert_eq!(s["state"]["group"], before["group"]);

    // Coordinator from recovery data.
    let mut c = wallet("coordinator");
    let s = import(&mut c, &recovery);
    assert_eq!(s["state"]["group"], state(&mut g.coordinator)["group"]);

    // The restored wallets can sign together with an original one.
    g.participants[1] = a;
    g.coordinator = c;
    let signature = sign(&mut g, &[1, 2], b"restored", json!([]));
    assert_eq!(signature["pubkey"], before["group"]["xonly"]);
}

#[test]
fn misrouted_and_damaged_messages_are_rejected() {
    let mut g = keygen(2, 2);
    let share = call(
        &mut g.participants[0],
        json!({ "op": "export", "what": "share" }),
    )["result"]["data"]
        .clone();

    // Secrets are refused by a coordinator.
    let err = try_call(&mut g.coordinator, json!({ "op": "import", "data": share })).unwrap_err();
    assert!(err.contains("SECRET"), "{err}");

    // A single flipped character fails the checksum.
    let text = share.as_str().unwrap();
    let flip = if text.as_bytes()[20] == b'A' {
        "B"
    } else {
        "A"
    };
    let damaged = format!("{}{}{}", &text[..20], flip, &text[21..]);
    let mut p = wallet("participant");
    let err = try_call(&mut p, json!({ "op": "import", "data": damaged })).unwrap_err();
    assert!(err.contains("Checksum"), "{err}");
    assert!(try_call(&mut p, json!({ "op": "import", "data": "hello" })).is_err());

    // Whitespace, padding and the URL-safe alphabet are tolerated.
    let mangled: String = text
        .chars()
        .enumerate()
        .flat_map(|(i, c)| {
            let c = match c {
                '+' => '-',
                '/' => '_',
                c => c,
            };
            (i % 40 == 39).then_some('\n').into_iter().chain([c])
        })
        .collect();
    import(&mut p, &json!(format!("  {mangled}==\n")));

    // A signing request for another group is refused.
    let mut other = keygen(2, 1);
    let s = call(
        &mut other.coordinator,
        json!({ "op": "c_sign_start", "msg": "00", "tweaks": [] }),
    );
    let err = try_call(
        &mut g.participants[0],
        json!({ "op": "import", "data": s["state"]["sign"]["request"]["data"] }),
    )
    .unwrap_err();
    assert!(err.contains("different group"), "{err}");
}

#[test]
fn too_few_nonces_are_refused() {
    let mut g = keygen(3, 2);
    let s = call(
        &mut g.coordinator,
        json!({ "op": "c_sign_start", "msg": "00", "tweaks": [] }),
    );
    let p = &mut g.participants[0];
    import(p, &s["state"]["sign"]["request"]["data"]);
    let s = call(p, json!({ "op": "p_sign_approve" }));
    import(&mut g.coordinator, &s["state"]["sign"]["out"]["data"]);
    // Refused up front, so the session survives and can still collect nonces.
    assert!(try_call(&mut g.coordinator, json!({ "op": "c_sign_package" })).is_err());
    assert_eq!(state(&mut g.coordinator)["sign"]["stage"], "round1");
}

#[test]
fn user_entropy_for_the_host_key() {
    let host = |w: &mut Wallet, extra: Value| {
        let mut req = json!({ "op": "p_new_host" });
        req.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        try_call(w, req).map(|r| r["state"]["host"]["pubkey"].clone())
    };
    // A fixed "random" source makes the effect of the added input visible.
    let fixed = |extra: Value| {
        let mut w = Wallet::new(Box::new(|buf: &mut [u8]| buf.fill(0x42)));
        call(&mut w, json!({ "op": "set_role", "role": "participant" }));
        host(&mut w, extra)
    };
    let plain = fixed(json!({})).unwrap();
    let dice = fixed(json!({ "dice": "16342" })).unwrap();
    assert_ne!(plain, dice);
    assert_eq!(dice, fixed(json!({ "dice": "16342" })).unwrap());
    assert_ne!(dice, fixed(json!({ "dice": "16343" })).unwrap());
    assert_ne!(dice, fixed(json!({ "coins": "HTTHT" })).unwrap());
    assert_ne!(
        dice,
        fixed(json!({ "dice": "16342", "drawing": [1.5, 2.0, 3.25] })).unwrap()
    );
    assert!(fixed(json!({ "dice": "1637" })).is_err());
    assert!(fixed(json!({ "drawing": [1.0, 2.0] })).is_err());
    assert!(fixed(json!({ "drawing": [1.0, "x", 3.0] })).is_err());
    assert!(fixed(json!({ "coins": "HX" })).is_err());

    // With device randomness the same input never gives the same key.
    let mixed = json!({ "coins": "HTTH" });
    assert_ne!(
        host(&mut wallet("participant"), mixed.clone()).unwrap(),
        host(&mut wallet("participant"), mixed).unwrap()
    );

    // Without it the key depends on the input alone, and the input has to
    // carry 128 bits: 50 rolls do, 49 do not, and a drawing never counts.
    let rolls = "1234561234".repeat(5);
    let alone = json!({ "device": false, "dice": rolls });
    let key = host(&mut wallet("participant"), alone.clone()).unwrap();
    assert_eq!(key, host(&mut wallet("participant"), alone).unwrap());
    assert_eq!(
        key,
        fixed(json!({ "device": false, "dice": rolls })).unwrap()
    );
    assert_ne!(key, fixed(json!({ "dice": rolls })).unwrap());

    let alone = |extra: Value| {
        let mut req = json!({ "device": false });
        req.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        host(&mut wallet("participant"), req)
    };
    let short = alone(json!({ "dice": &rolls[..49] }));
    assert!(short.unwrap_err().contains("128 bits"));

    let path = (0..5000)
        .flat_map(|i| [i as f64, 2.0, i as f64])
        .collect::<Vec<_>>();
    assert!(alone(json!({ "dice": &rolls[..49], "drawing": path })).is_err());
    assert!(alone(json!({ "drawing": path })).is_err());
    assert!(host(&mut wallet("participant"), json!({ "device": false })).is_err());
    let flips = json!({ "device": false, "coins": "HT".repeat(64) });
    assert!(host(&mut wallet("participant"), flips).is_ok());
    let mix = json!({ "device": false, "dice": &rolls[..25], "coins": "HT".repeat(32) });
    assert!(host(&mut wallet("participant"), mix).is_ok());
}
