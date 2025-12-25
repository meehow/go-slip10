package slip10

import (
	"encoding/hex"
	"testing"
)

type slipTestCase struct {
	path              string
	parentFingerprint string
	chainCode         string
	privKey           string
	pubKey            string
}

func TestSlip10PythonVectors(t *testing.T) {
	seed1 := "000102030405060708090a0b0c0d0e0f"
	seed2 := "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"

	vectors := []struct {
		name      string
		seed      string
		curveName string
		nodes     []slipTestCase
	}{
		{
			name:      "Vector 1 secp256k1",
			seed:      seed1,
			curveName: "secp256k1",
			nodes: []slipTestCase{
				{"m", "00000000", "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508", "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35", "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"},
				{"m/0h", "3442193e", "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141", "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea", "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56"},
				{"m/0h/1", "5c1bd648", "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19", "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368", "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c"},
				{"m/0h/1/2h", "bef5a2f9", "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f", "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca", "0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2"},
				{"m/0h/1/2h/2", "ee7ab90c", "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd", "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4", "02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29"},
				{"m/0h/1/2h/2/1000000000", "d880d7d8", "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e", "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8", "022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011"},
			},
		},
		{
			name:      "Vector 1 nist256p1",
			seed:      seed1,
			curveName: "nist256p1",
			nodes: []slipTestCase{
				{"m", "00000000", "beeb672fe4621673f722f38529c07392fecaa61015c80c34f29ce8b41b3cb6ea", "612091aaa12e22dd2abef664f8a01a82cae99ad7441b7ef8110424915c268bc2", "0266874dc6ade47b3ecd096745ca09bcd29638dd52c2c12117b11ed3e458cfa9e8"},
				{"m/0h", "be6105b5", "3460cea53e6a6bb5fb391eeef3237ffd8724bf0a40e94943c98b83825342ee11", "6939694369114c67917a182c59ddb8cafc3004e63ca5d3b84403ba8613debc0c", "0384610f5ecffe8fda089363a41f56a5c7ffc1d81b59a612d0d649b2d22355590c"},
				{"m/0h/1", "9b02312f", "4187afff1aafa8445010097fb99d23aee9f599450c7bd140b6826ac22ba21d0c", "284e9d38d07d21e4e281b645089a94f4cf5a5a81369acf151a1c3a57f18b2129", "03526c63f8d0b4bbbf9c80df553fe66742df4676b241dabefdef67733e070f6844"},
				{"m/0h/1/2h", "b98005c1", "98c7514f562e64e74170cc3cf304ee1ce54d6b6da4f880f313e8204c2a185318", "694596e8a54f252c960eb771a3c41e7e32496d03b954aeb90f61635b8e092aa7", "0359cf160040778a4b14c5f4d7b76e327ccc8c4a6086dd9451b7482b5a4972dda0"},
				{"m/0h/1/2h/2", "0e9f3274", "ba96f776a5c3907d7fd48bde5620ee374d4acfd540378476019eab70790c63a0", "5996c37fd3dd2679039b23ed6f70b506c6b56b3cb5e424681fb0fa64caf82aaa", "029f871f4cb9e1c97f9f4de9ccd0d4a2f2a171110c61178f84430062230833ff20"},
				{"m/0h/1/2h/2/1000000000", "8b2b5c4b", "b9b7b82d326bb9cb5b5b121066feea4eb93d5241103c9e7a18aad40f1dde8059", "21c4f269ef0a5fd1badf47eeacebeeaa3de22eb8e5b0adcd0f27dd99d34d0119", "02216cd26d31147f72427a453c443ed2cde8a1e53c9cc44e5ddf739725413fe3f4"},
			},
		},
		{
			name:      "Vector 1 ed25519",
			seed:      seed1,
			curveName: "ed25519",
			nodes: []slipTestCase{
				{"m", "00000000", "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb", "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7", "00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"},
				{"m/0h", "ddebc675", "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69", "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3", "008c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c"},
				{"m/0h/1h", "13dab143", "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14", "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2", "001932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187"},
				{"m/0h/1h/2h", "ebe4cb29", "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c", "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9", "00ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1"},
				{"m/0h/1h/2h/2h", "316ec1c6", "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc", "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662", "008abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c"},
				{"m/0h/1h/2h/2h/1000000000h", "d6322ccd", "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230", "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793", "003c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a"},
			},
		},
		{
			name:      "Vector 1 curve25519",
			seed:      seed1,
			curveName: "curve25519",
			nodes: []slipTestCase{
				{"m", "00000000", "77997ca3588a1a34f3589279ea2962247abfe5277d52770a44c706378c710768", "d70a59c2e68b836cc4bbe8bcae425169b9e2384f3905091e3d60b890e90cd92c", "005c7289dc9f7f3ea1c8c2de7323b9fb0781f69c9ecd6de4f095ac89a02dc80577"},
				{"m/0h", "6f5a9c0d", "349a3973aad771c628bf1f1b4d5e071f18eff2e492e4aa7972a7e43895d6597f", "cd7630d7513cbe80515f7317cdb9a47ad4a56b63c3f1dc29583ab8d4cc25a9b2", "00cb8be6b256ce509008b43ae0dccd69960ad4f7ff2e2868c1fbc9e19ec3ad544b"},
				{"m/0h/1h", "fde474d7", "2ee5ba14faf2fe9d7ab532451c2be3a0a5375c5e8c44fb31d9ad7edc25cda000", "a95f97cfc1a61dd833b882c89d36a78a030ea6b2fbe3ae2a70e4f1fc9008d6b1", "00e9506455dce2526df42e5e4eb5585eaef712e5f9c6a28bf9fb175d96595ea872"},
				{"m/0h/1h/2h", "6569dde7", "e1897d5a96459ce2a3d294cb2a6a59050ee61255818c50e03ac4263ef17af084", "3d6cce04a9175929da907a90b02176077b9ae050dcef9b959fed978bb2200cdc", "0018f008fcbc6d1cd8b4fe7a9eba00f6570a9da02a9b0005028cb2731b12ee4118"},
				{"m/0h/1h/2h/2h", "1b7cce71", "1cccc84e2737cfe81b51fbe4c97bbdb000f6a76eddffb9ed03108fbff3ff7e4f", "7ae7437efe0a3018999e6f00d72e810ebc50578dbf6728bfa1c7fe73501081a7", "00512e288a8ef4d869620dc4b06bb06ad2524b350dee5a39fcfeb708dbac65c25c"},
				{"m/0h/1h/2h/2h/1000000000h", "de5dcb65", "8ccf15d55b1dda246b0c1bf3e979a471a82524c1bd0c1eaecccf00dde72168bb", "7a59954d387abde3bc703f531f67d659ec2b8a12597ae82824547d7e27991e26", "00a077fcf5af53d210257d44a86eb2031233ac7237da220434ac01a0bebccc1919"},
			},
		},
		{
			name:      "Vector 2 secp256k1",
			seed:      seed2,
			curveName: "secp256k1",
			nodes: []slipTestCase{
				{"m", "00000000", "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689", "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e", "03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7"},
				{"m/0", "bd16bee5", "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c", "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e", "02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea"},
				{"m/0/2147483647h", "5a61ff8e", "be17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d9", "877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93", "03c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b"},
				{"m/0/2147483647h/1", "d8ab4937", "f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb", "704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7", "03a7d1d856deb74c508e05031f9895dab54626251b3806e16b4bd12e781a7df5b9"},
				{"m/0/2147483647h/1/2147483646h", "78412e3a", "637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e29", "f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d", "02d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0"},
				{"m/0/2147483647h/1/2147483646h/2", "31a507b8", "9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271", "bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23", "024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c"},
			},
		},
		{
			name:      "Retry secp256r1",
			seed:      seed1,
			curveName: "nist256p1",
			nodes: []slipTestCase{
				{"m/28578h", "be6105b5", "e94c8ebe30c2250a14713212f6449b20f3329105ea15b652ca5bdfc68f6c65c2", "06f0db126f023755d0b8d86d4591718a5210dd8d024e3e14b6159d63f53aa669", "02519b5554a4872e8c9c1c847115363051ec43e93400e030ba3c36b52a3e70a5b7"},
				{"m/28578h/33941", "3e2b7bc6", "9e87fe95031f14736774cd82f25fd885065cb7c358c1edf813c72af535e83071", "092154eed4af83e078ff9b84322015aefe5769e31270f62c3f66c33888335f3a", "0235bfee614c0d5b2cae260000bb1d0d84b270099ad790022c1ae0b2e782efe120"},
			},
		},
		{
			name:      "Seed retry secp256r1",
			seed:      "a7305bc8df8d0951f0cb224c0e95d7707cbdf2c6ce7e8d481fec69c7ff5e9446",
			curveName: "nist256p1",
			nodes: []slipTestCase{
				{"m", "00000000", "7762f9729fed06121fd13f326884c82f59aa95c57ac492ce8c9654e60efd130c", "3b8c18469a4634517d6d0b65448f8e6c62091b45540a1743c5846be55d47d88f", "0383619fadcde31063d8c5cb00dbfe1713f3e6fa169d8541a798752a1c1ca0cb20"},
			},
		},
	}

	curves := map[string]Curve{
		"secp256k1":  NewSecp256k1(),
		"nist256p1":  NewNist256p1(),
		"ed25519":    NewEd25519(),
		"curve25519": NewCurve25519(),
	}

	for _, tt := range vectors {
		t.Run(tt.name, func(t *testing.T) {
			curve := curves[tt.curveName]
			seed, _ := hex.DecodeString(tt.seed)
			master, err := NewMasterNode(seed, curve)
			if err != nil {
				t.Fatalf("failed to create master node: %v", err)
			}

			for _, tc := range tt.nodes {
				node, err := master.DerivePath(tc.path)
				if err != nil {
					t.Fatalf("failed to derive path %s: %v", tc.path, err)
				}

				if hex.EncodeToString(node.ParentFP) != tc.parentFingerprint {
					t.Errorf("path %s: expected parent fingerprint %s, got %s", tc.path, tc.parentFingerprint, hex.EncodeToString(node.ParentFP))
				}
				if hex.EncodeToString(node.ChainCode) != tc.chainCode {
					t.Errorf("path %s: expected chain code %s, got %s", tc.path, tc.chainCode, hex.EncodeToString(node.ChainCode))
				}
				if hex.EncodeToString(node.PrivKey) != tc.privKey {
					t.Errorf("path %s: expected privKey %s, got %s", tc.path, tc.privKey, hex.EncodeToString(node.PrivKey))
				}
				if hex.EncodeToString(node.PublicKey()) != tc.pubKey {
					t.Errorf("path %s: expected pubKey %s, got %s", tc.path, tc.pubKey, hex.EncodeToString(node.PublicKey()))
				}
			}
		})
	}
}

func TestBip32Vectors(t *testing.T) {
	curve := NewSecp256k1()
	seed1, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")

	t.Run("Vector 1", func(t *testing.T) {
		master, _ := NewMasterNode(seed1, curve)

		expectedXPub := "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
		expectedXPriv := "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"

		if master.XPub() != expectedXPub {
			t.Errorf("expected xpub %s, got %s", expectedXPub, master.XPub())
		}
		if master.XPriv() != expectedXPriv {
			t.Errorf("expected xpriv %s, got %s", expectedXPriv, master.XPriv())
		}

		// m/0H
		node, _ := master.DerivePath("m/0H")
		expectedXPub = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
		expectedXPriv = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
		if node.XPub() != expectedXPub {
			t.Errorf("m/0H: expected xpub %s, got %s", expectedXPub, node.XPub())
		}
		if node.XPriv() != expectedXPriv {
			t.Errorf("m/0H: expected xpriv %s, got %s", expectedXPriv, node.XPriv())
		}
	})

	t.Run("Invalid keys", func(t *testing.T) {
		invalidXPubs := []string{
			"xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm",
			"xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn",
		}
		for _, xpub := range invalidXPubs {
			_, err := NewNodeFromExtendedKey(xpub, curve)
			if err == nil {
				t.Errorf("expected error for invalid xpub %s", xpub)
			}
		}
	})
}

func TestBip39MnemonicToSeed(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	passphrase := "TREZOR"
	expectedSeed := "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"

	seed := MnemonicToSeed(mnemonic, passphrase)
	if hex.EncodeToString(seed) != expectedSeed {
		t.Errorf("expected seed %s, got %s", expectedSeed, hex.EncodeToString(seed))
	}
}

func TestCrossCheckSeedXPriv(t *testing.T) {
	seed, _ := hex.DecodeString("1077a46dc8545d372f22d9e110ae6c5c2bf7620fe9c4c911f5404d112233e1aa270567dd3554092e051ba3ba86c303590b0309116ac89964ff284db2219d7511")
	curve := NewSecp256k1()

	node1, _ := NewMasterNode(seed, curve)
	xpriv := node1.XPriv()

	node2, err := NewNodeFromExtendedKey(xpriv, curve)
	if err != nil {
		t.Fatalf("failed to create node from xpriv: %v", err)
	}

	if node1.XPub() != node2.XPub() {
		t.Errorf("xpub mismatch")
	}
}

func TestPublicDerivation(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	seed := MnemonicToSeed(mnemonic, "TREZOR")

	// Master Node (Private)
	master, _ := NewMasterNode(seed, NewSecp256k1())

	// Derive m/0 (Private)
	childPriv, _ := master.Derive(0)

	// Public Parent: m/0 public
	// Manually construct public node to simulate starting from xpub
	pubParent := &Node{
		Curve:     NewSecp256k1(),
		IsPrivate: false,
		PrivKey:   nil,
		PubKey:    childPriv.PubKey,
		ChainCode: childPriv.ChainCode,
		Depth:     childPriv.Depth,
		ParentFP:  childPriv.ParentFP,
		Index:     childPriv.Index,
		Version:   VersionMainPublic,
	}

	// Derive m/0/1 (Public) from Public Parent
	childPubFromPub, err := pubParent.Derive(1)
	if err != nil {
		t.Fatalf("public derivation failed: %v", err)
	}

	// Derive m/0/1 (Private) from Private Parent
	childPrivFromPriv, _ := childPriv.Derive(1)

	// Compare Public Keys
	if hex.EncodeToString(childPubFromPub.PubKey) != hex.EncodeToString(childPrivFromPriv.PubKey) {
		t.Errorf("public comparison failed: got %s, want %s", hex.EncodeToString(childPubFromPub.PubKey), hex.EncodeToString(childPrivFromPriv.PubKey))
	}
}
