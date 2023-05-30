use halo2_curves::bn256::{Bn256, G1Affine, Fr};
use halo2_proofs::{poly::{kzg::{multiopen::{ProverGWC, VerifierGWC}, strategy::AccumulatorStrategy, commitment::ParamsKZG}, VerificationStrategy, commitment::{Params, ParamsProver}}, plonk::{VerifyingKey, ProvingKey, Circuit, verify_proof, create_proof}, dev::MockProver};
use itertools::Itertools;
use rand_core::OsRng;
use crate::halo2_proofs::{
    poly::kzg::{
        commitment::KZGCommitmentScheme,
    },
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
};
use std::{rc::Rc};

use snark_verifier::{
    loader::evm::{encode_calldata, Address, EvmLoader, ExecutorBuilder, self},
    pcs::kzg::{Gwc19, KzgAs},
    system::halo2::{compile, transcript::evm::EvmTranscript, Config}, verifier::{self, SnarkVerifier},
};

type PlonkVerifier = verifier::plonk::PlonkVerifier<KzgAs<Bn256, Gwc19>>;

fn gen_proof<C: Circuit<Fr>>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
    instances: Vec<Vec<Fr>>,
) -> Vec<u8> {
    let cs = pk.get_vk().cs();
    println!("num_instance_columns: {:?}", cs.num_instance_columns());
    println!("params.k() {:?}", params.k());
    MockProver::run(params.k(), &circuit, instances.clone())
        .unwrap()
        .assert_satisfied();

    let instances = instances
        .iter()
        .map(|instances| instances.as_slice())
        .collect_vec();
    let proof = {
        let mut transcript = TranscriptWriterBuffer::<_, G1Affine, _>::init(Vec::new());
        create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, EvmTranscript<_, _, _, _>, _>(
            params,
            pk,
            &[circuit],
            &[instances.as_slice()],
            OsRng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };

    let accept = {
        let mut transcript = TranscriptReadBuffer::<_, G1Affine, _>::init(proof.as_slice());
        VerificationStrategy::<_, VerifierGWC<_>>::finalize(
            verify_proof::<_, VerifierGWC<_>, _, EvmTranscript<_, _, _, _>, _>(
                params.verifier_params(),
                pk.get_vk(),
                AccumulatorStrategy::new(params.verifier_params()),
                &[instances.as_slice()],
                &mut transcript,
            )
            .unwrap(),
        )
    };
    assert!(accept);

    proof
}

fn gen_evm_verifier(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    num_instance: Vec<usize>,
) -> Vec<u8> {
    let protocol = compile(
        params,
        vk,
        Config::kzg().with_num_instance(num_instance.clone()),
    );
    let vk = (params.get_g()[0], params.g2(), params.s_g2()).into();

    let loader = EvmLoader::new::<halo2_curves::bn256::Fq, Fr>();
    let protocol = protocol.loaded(&loader);
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

    let instances = transcript.load_instances(num_instance);
    let proof = PlonkVerifier::read_proof(&vk, &protocol, &instances, &mut transcript).unwrap();
    PlonkVerifier::verify(&vk, &protocol, &instances, &proof).unwrap();

    evm::compile_yul(&loader.yul_code())
}

pub struct EvmVerifier {
    params: ParamsKZG<Bn256>,
    pk: ProvingKey<G1Affine>,
    bytecode: Vec<u8>,
}

fn evm_verify(deployment_code: Vec<u8>, instances: Vec<Vec<Fr>>, proof: Vec<u8>) {
    let mut calldata = encode_calldata(&instances, &proof);
    let success = {
        let mut evm = ExecutorBuilder::default()
            .with_gas_limit(u64::MAX.into())
            .build();

        let caller = Address::from_low_u64_be(0xfe);
        // println!("{:?}", evm.deploy(caller, deployment_code.clone().into(), 0.into()));
        let verifier = evm
            .deploy(caller, deployment_code.clone().into(), 0.into())
            .address
            .unwrap();
        println!("deployment_code: {:?}", deployment_code.iter().map(|b| format!("{:02x}", b).to_string()).collect::<Vec<String>>().join(""));
        println!("calldata: {:?}", calldata.iter().map(|b| format!("{:02x}", b).to_string()).collect::<Vec<String>>().join(""));
        // calldata[1] += 1;
        let result = evm.call_raw(caller, verifier, calldata.into(), 0.into());

        dbg!(result.gas_used);

        !result.reverted
    };
    assert!(success);
}

impl EvmVerifier {
    pub fn new(params: ParamsKZG<Bn256>, pk: ProvingKey<G1Affine>, num_instance: Vec<usize>) -> Self {
        let deployment_code = gen_evm_verifier(&params, pk.get_vk(), num_instance);
        Self { params: params, pk: pk, bytecode: deployment_code }
    }

    /// Verifies the proof with EVM byte code. Panics if verification fails.
    pub fn verify(&self, instances: Vec<Vec<Fr>>, proof: Vec<u8>) {
        evm_verify(self.bytecode.clone(), instances, proof)
    }

    pub fn gen_proof<C: Circuit<Fr>>(&self, circuit: C, instances: Vec<Vec<Fr>>) -> Vec<u8> {
        gen_proof(&self.params, &self.pk, circuit, instances)
    }
}