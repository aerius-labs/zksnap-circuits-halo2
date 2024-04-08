self.onmessage = async (e) => {
    if (e.data.action === "runMain") {
        try {
            const {
                default: init,
                initThreadPool,
                initPanicHook,
                Halo2Wasm,
                MyCircuit,
            } = await import("../wasm/pkg/wasm");

            function fetchProposalId() {}

            
            async function fetchUserData() {
                try {
                    const response = await fetch(`http://localhost:8080/proposal/send_voter_dto/6607fa5217f3c0572df17c01/0x11f2b30c9479ccaa639962e943ca7cfd3498705258ddb49dfe25bba00a555e48cb35a79f3d084ce26dbac0e6bb887463774817cb80e89b20c0990bc47f9075d5`);
                    if (!response.ok) {
                        throw new Error('Network response was not ok');
                    }
                    const data = await response.json();
                    console.log(data);
                    return data;
                } catch (error) {
                    console.error("Error:", error);
                    // Optionally, handle the error (e.g., update UI to show an error message).
                    return null; // Or handle the failure case appropriately.
                }
            }
            

            // function encVote(m, r, n, g) {
            //     let n2 = n * n;
            //     let gm = g ** m;
            //     let rn = r ** n;
            //     let c = (gm * rn) % n2;

            // // get vote
            // // generate vote_enc
            // let vote = [1, 0, 0, 0, 0];
            // let voteEnc = [];
            // for (i = 0; i < vote.length; i++) {
            //     voteEnc.push(encVote(vote[i], r, pkEnc.n, pkEnc.g));
            // }

            // // Generate Nullifier Code.
            // // Note: Only works with Taho Wallet (https://github.com/tahowallet/extension/pull/3638)
            // await window.ethereum.request({
            //     method: "eth_requestAccounts",
            //     params: [],
            // });

            // accountAddress = (
            //     await window.ethereum.request({
            //         method: "eth_accounts",
            //         params: [],
            //     })
            // )[0];

            // let nullifier = await window.ethereum.request({
            //     method: "eth_getPlumeSignature",
            //     params: ["this is a test message - hi aayush", accountAddress],
            // });

            // let wasmInput = {
            //     membership_root: Fr,
            //     pk_enc: EncryptionPublicKey,
            //     nullifier: Secp256k1Affine,
            //     proposal_id: Fr,
            //     vote_enc: Vec<BigUint>,
            //     s_nullifier: Fq,
            //     vote: Vec<Fr>,
            //     r_enc: Vec<BigUint>,
            //     pk_voter: Secp256k1Affine,
            //     c_nullifier: Fq,
            //     membership_proof: Vec<Fr>,
            //     membership_proof_helper: Vec<Fr>,
            // };

            let data = await fetchUserData();
            console.log(data);

            await init();
            console.log("Wasm initialized");

            initPanicHook();
            console.log("Panic hook initialized");

            await initThreadPool(navigator.hardwareConcurrency);
            console.log("Thread pool initialized");

            const halo2wasm = new Halo2Wasm();
            console.log("Halo2Wasm instance created");

            halo2wasm.config({
                k: 15,
                numAdvice: 412,
                numLookupAdvice: 11,
                numInstance: 1,
                numLookupBits: 14,
                numVirtualInstance: 1,
            });
            console.log("Halo2Wasm configured");

            const myCircuit = new MyCircuit(halo2wasm);
            console.log("MyCircuit instance created");

            myCircuit.run();
            console.log("MyCircuit run method called");

            halo2wasm.useInstances();
            console.log("Instances used");

            let instanceValues = halo2wasm.getInstanceValues(0);
            console.log("instanceValues:", instanceValues);

            let instances = halo2wasm.getInstances(0);
            console.log("instances:", instances);

            let stats = halo2wasm.getCircuitStats();
            console.log("Circuit stats:", stats);

            let params = await getKzgParams(15);
            console.log("KZG params:", params);

            halo2wasm.loadParams(params);
            console.log("KZG params loaded");

            halo2wasm.mock();
            console.log("Mock called");

            const start = performance.now();
            halo2wasm.genVk();
            const end = performance.now();
            console.log(
                "Verification key generated in",
                end - start,
                "milliseconds"
            );

            const pkStart = performance.now();
            halo2wasm.genPk();
            const pkEnd = performance.now();
            console.log(
                "Proving key generated in",
                pkEnd - pkStart,
                "milliseconds"
            );

            const proofStart = performance.now();
            let proof = halo2wasm.prove();
            const proofEnd = performance.now();
            console.log(
                "Proof generated:",
                proof,
                "in",
                proofEnd - proofStart,
                "milliseconds"
            );

            const verifyStart = performance.now();
            halo2wasm.verify(proof);
            const verifyEnd = performance.now();
            console.log(
                "Proof verified in",
                verifyEnd - verifyStart,
                "milliseconds"
            );

            console.log("Main function completed successfully");
            self.postMessage({
                status: "success",
                message: "Main function executed successfully",
            });
        } catch (error) {
            console.error("Error running main function:", error);
            self.postMessage({
                status: "error",
                message: "Error running main function",
            });
        }
    }
};

const fetchAndConvertToUint8Array = (url) => {
    return new Promise((resolve, reject) => {
        // Check if running in Node.js environment
        if (
            typeof process !== "undefined" &&
            process.versions &&
            process.versions.node
        ) {
            const https = require("https");
            https.get(url, (res) => {
                let chunks = [];
                res.on("data", (chunk) => chunks.push(chunk));
                res.on("end", () => {
                    let binaryData = Buffer.concat(chunks);
                    resolve(new Uint8Array(binaryData));
                });
                res.on("error", reject);
            });
        }
        // Check if running in browser or web worker environment
        else if (typeof window !== "undefined" || typeof self !== "undefined") {
            fetch(url)
                .then((response) => response.arrayBuffer())
                .then((buffer) => {
                    resolve(new Uint8Array(buffer));
                })
                .catch(reject);
        } else {
            reject(new Error("Environment not supported"));
        }
    });
};

const getKzgParams = async (k) => {
    if (k < 6 || k > 19) {
        throw new Error(`k=${k} is not supported`);
    }
    return await fetchAndConvertToUint8Array(
        `https://axiom-crypto.s3.amazonaws.com/challenge_0085/kzg_bn254_${k}.srs`
    );
};
