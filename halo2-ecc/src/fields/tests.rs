mod fp {
    use crate::fields::{
        fp::{FpConfig, FpStrategy},
        FieldChip,
    };
    use crate::halo2_proofs::{
        circuit::*,
        dev::MockProver,
        halo2curves::bn256::{Fq, Fr},
        plonk::*,
    };
    use group::ff::Field;
    use halo2_base::{
        utils::{fe_to_biguint, modulus, PrimeField},
        SKIP_FIRST_PASS,
    };
    use num_bigint::BigInt;
    use rand::rngs::OsRng;
    use std::marker::PhantomData;

    #[derive(Default)]
    struct MyCircuit<F> {
        a: Value<Fq>,
        b: Value<Fq>,
        _marker: PhantomData<F>,
    }

    const NUM_ADVICE: usize = 1;
    const NUM_FIXED: usize = 1;
    const K: usize = 10;

    impl<F: PrimeField> Circuit<F> for MyCircuit<F> {
        type Config = FpConfig<F, Fq>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            FpConfig::<F, _>::configure(
                meta,
                FpStrategy::Simple,
                &[NUM_ADVICE],
                &[1],
                NUM_FIXED,
                9,
                88,
                3,
                modulus::<Fq>(),
                0,
                K,
            )
        }

        fn synthesize(
            &self,
            chip: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            chip.load_lookup_table(&mut layouter)?;

            let mut first_pass = SKIP_FIRST_PASS;

            layouter.assign_region(
                || "fp",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }

                    let mut aux = chip.new_context(region);
                    let ctx = &mut aux;

                    let a_assigned =
                        chip.load_private(ctx, self.a.map(|a| BigInt::from(fe_to_biguint(&a))));
                    let b_assigned =
                        chip.load_private(ctx, self.b.map(|b| BigInt::from(fe_to_biguint(&b))));

                    // test fp_multiply
                    {
                        chip.mul(ctx, &a_assigned, &b_assigned);
                    }

                    // IMPORTANT: this copies advice cells to enable lookup
                    // This is not optional.
                    chip.finalize(ctx);

                    #[cfg(feature = "display")]
                    {
                        println!(
                            "Using {NUM_ADVICE} advice columns and {NUM_FIXED} fixed columns"
                        );
                        println!("total cells: {}", ctx.total_advice);

                        let (const_rows, _) = ctx.fixed_stats();
                        println!("maximum rows used by a fixed column: {const_rows}");
                    }
                    Ok(())
                },
            )
        }
    }

    #[test]
    fn test_fp() {
        let a = Fq::random(OsRng);
        let b = Fq::random(OsRng);

        let circuit =
            MyCircuit::<Fr> { a: Value::known(a), b: Value::known(b), _marker: PhantomData };

        let prover = MockProver::run(K as u32, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
        //assert_eq!(prover.verify(), Ok(()));
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn plot_fp() {
        use plotters::prelude::*;

        let root = BitMapBackend::new("layout.png", (1024, 1024)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root.titled("Fp Layout", ("sans-serif", 60)).unwrap();

        let circuit = MyCircuit::<Fr>::default();
        halo2_proofs::dev::CircuitLayout::default().render(K as u32, &circuit, &root).unwrap();
    }
}

mod fp12 {
    use crate::fields::{
        fp::{FpConfig, FpStrategy},
        fp12::*,
        FieldChip,
    };
    use crate::halo2_proofs::{
        circuit::*,
        dev::MockProver,
        halo2curves::bn256::{Fq, Fq12, Fr},
        plonk::*,
    };
    use ark_std::{start_timer, end_timer};
    use halo2_base::utils::{modulus, fs::gen_srs};
    use halo2_base::{utils::PrimeField, SKIP_FIRST_PASS};
    use halo2_curves::bn256::{Bn256, G1Affine};
    use halo2_proofs::{poly::{kzg::{commitment::{ParamsKZG, KZGCommitmentScheme}, multiopen::{ProverGWC, VerifierGWC}, strategy::AccumulatorStrategy}, commitment::{Params, ParamsProver}, VerificationStrategy}, transcript::{TranscriptWriterBuffer, TranscriptReadBuffer}};
    use itertools::Itertools;
    use rand_core::OsRng;
    use snark_verifier::{
        loader::evm::{encode_calldata, Address, EvmLoader, ExecutorBuilder, self},
        pcs::kzg::{Gwc19, KzgAs},
        system::halo2::{compile, transcript::evm::EvmTranscript, Config}, verifier::{self, SnarkVerifier},
    };
    use std::{marker::PhantomData, rc::Rc};

    #[derive(Default)]
    struct MyCircuit<F> {
        a: Value<Fq12>,
        b: Value<Fq12>,
        _marker: PhantomData<F>,
    }

    const NUM_ADVICE: usize = 1;
    const NUM_FIXED: usize = 1;
    const XI_0: i64 = 9;

    impl<F: PrimeField> Circuit<F> for MyCircuit<F> {
        type Config = FpConfig<F, Fq>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            FpConfig::<F, _>::configure(
                meta,
                FpStrategy::Simple,
                &[NUM_ADVICE],
                &[1],
                NUM_FIXED,
                22,
                88,
                3,
                modulus::<Fq>(),
                0,
                23,
            )
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            config.load_lookup_table(&mut layouter)?;
            let chip = Fp12Chip::<F, FpConfig<F, Fq>, Fq12, XI_0>::construct(&config);

            let mut first_pass = SKIP_FIRST_PASS;

            layouter.assign_region(
                || "fp12",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }

                    let mut aux = config.new_context(region);
                    let ctx = &mut aux;

                    let a_assigned = chip.load_private(
                        ctx,
                        Fp12Chip::<F, FpConfig<F, Fq>, Fq12, XI_0>::fe_to_witness(&self.a),
                    );
                    let b_assigned = chip.load_private(
                        ctx,
                        Fp12Chip::<F, FpConfig<F, Fq>, Fq12, XI_0>::fe_to_witness(&self.b),
                    );

                    // test fp_multiply
                    {
                        chip.mul(ctx, &a_assigned, &b_assigned);
                    }

                    // IMPORTANT: this copies advice cells to enable lookup
                    // This is not optional.
                    chip.fp_chip.finalize(ctx);

                    #[cfg(feature = "display")]
                    {
                        println!(
                            "Using {NUM_ADVICE} advice columns and {NUM_FIXED} fixed columns"
                        );
                        println!("total advice cells: {}", ctx.total_advice);

                        let (const_rows, _) = ctx.fixed_stats();
                        println!("maximum rows used by a fixed column: {const_rows}");
                    }
                    Ok(())
                },
            )
        }
    }

    #[test]
    fn test_fp12() {
        let k = 23;
        let mut rng = rand::thread_rng();
        let a = Fq12::random(&mut rng);
        let b = Fq12::random(&mut rng);

        let circuit =
            MyCircuit::<Fr> { a: Value::known(a), b: Value::known(b), _marker: PhantomData };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
        // assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_fp12_on_chain() -> Result<(), Box<dyn std::error::Error>> {
        let k = 23;
        let mut rng = rand::thread_rng();
        let a = Fq12::random(&mut rng);
        let b = Fq12::random(&mut rng);

        let circuit =
            MyCircuit::<Fr> { a: Value::known(a), b: Value::known(b), _marker: PhantomData };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();

        let params_time = start_timer!(|| "Time elapsed in circuit & params construction");
        let params = gen_srs(k);
        let circuit = MyCircuit::<Fr>::default();
        end_timer!(params_time);

        let vk_time = start_timer!(|| "Time elapsed in generating vkey");
        let vk = keygen_vk(&params, &circuit)?;
        end_timer!(vk_time);

        let pk_time = start_timer!(|| "Time elapsed in generating pkey");
        let pk = keygen_pk(&params, vk, &circuit)?;
        end_timer!(pk_time);
        // assert_eq!(prover.verify(), Ok(()));

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

            let loader = EvmLoader::new::<Fq, Fr>();
            let protocol = protocol.loaded(&loader);
            let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

            let instances = transcript.load_instances(num_instance);
            let proof = PlonkVerifier::read_proof(&vk, &protocol, &instances, &mut transcript).unwrap();
            PlonkVerifier::verify(&vk, &protocol, &instances, &proof).unwrap();

            evm::compile_yul(&loader.yul_code())
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

                // println!("result: {:?}", result);

                !result.reverted
            };
            assert!(success);
        }

        let deployment_code = gen_evm_verifier(&params, pk.get_vk(), vec![]);

        let proof_circuit =
            MyCircuit::<Fr> { a: Value::known(a), b: Value::known(b), _marker: PhantomData };

        let evm_proof = gen_proof(&params, &pk, proof_circuit, vec![]);
        evm_verify(deployment_code.clone(), vec![], evm_proof);



        let a = Fq12::random(&mut rng);
        let b = Fq12::random(&mut rng);

        let proof_circuit =
            MyCircuit::<Fr> { a: Value::known(a), b: Value::known(b), _marker: PhantomData };

        let evm_proof = gen_proof(&params, &pk, proof_circuit, vec![]);
        evm_verify(deployment_code, vec![], evm_proof);


        Ok(())
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn plot_fp12() {
        let k = 9;
        use plotters::prelude::*;

        let root = BitMapBackend::new("layout.png", (1024, 1024)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root.titled("Fp Layout", ("sans-serif", 60)).unwrap();

        let circuit = MyCircuit::<Fr>::default();
        halo2_proofs::dev::CircuitLayout::default().render(k, &circuit, &root).unwrap();
    }
}
