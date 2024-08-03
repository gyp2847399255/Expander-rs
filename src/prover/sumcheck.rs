use arith::{Field, FieldSerde, MultiLinearPoly};
use warp::redirect::see_other;

use crate::{CircuitLayer, Config, GkrScratchpad, SumcheckGkrHelper, Transcript};

// FIXME
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub fn sumcheck_prove_gkr_layer<F>(
    layer: &CircuitLayer<F>,
    rz0: &[Vec<F::BaseField>],
    rz1: &[Vec<F::BaseField>],
    alpha: &F::BaseField,
    beta: &F::BaseField,
    transcript: &mut Transcript,
    sp: &mut [GkrScratchpad<F>],
    config: &Config,
) -> (Vec<Vec<F::BaseField>>, Vec<Vec<F::BaseField>>)
where
    F: Field + FieldSerde,
{
    let mut helpers = vec![];
    assert_eq!(config.get_num_repetitions(), sp.len());
    for (j, sp_) in sp.iter_mut().enumerate() {
        helpers.push(SumcheckGkrHelper::new(
            layer, &rz0[j], &rz1[j], alpha, beta, sp_,
        ));
    }

    for i_var in 0..layer.input_var_num * 2 {
        for (j, helper) in helpers
            .iter_mut()
            .enumerate()
            .take(config.get_num_repetitions())
        {
            if i_var == 0 {
                helper.prepare_g_x_vals()
            }
            if i_var == layer.input_var_num {
                let vx_claim = helper.vx_claim();
                helper.prepare_h_y_vals(vx_claim)
            }

            let evals = helper.poly_evals_at(i_var, 2);

            transcript.append_f(evals[0]);
            transcript.append_f(evals[1]);
            transcript.append_f(evals[2]);

            let r = transcript.challenge_f::<F>();
            helper.receive_challenge(i_var, r);
            if i_var == layer.input_var_num - 1 {
                log::trace!("vx claim: {:?}", helper.vx_claim());
                transcript.append_f(helper.vx_claim());
            }
        }
    }

    for (j, helper) in helpers
        .iter()
        .enumerate()
        .take(config.get_num_repetitions())
    {
        log::trace!("claimed vy[{}] = {:?}", j, helper.vy_claim());
        transcript.append_f(helper.vy_claim());
    }

    let rz0s = (0..config.get_num_repetitions())
        .map(|j| helpers[j].rx.clone()) // FIXME: clone might be avoided
        .collect();
    let rz1s = (0..config.get_num_repetitions())
        .map(|j| helpers[j].ry.clone()) // FIXME: clone might be avoided
        .collect();
    (rz0s, rz1s)
}

pub fn merge_multilinear_evals<F: Field + FieldSerde>(
    poly: MultiLinearPoly<F>,
    zs: Vec<Vec<F::BaseField>>,
    transcript: &mut Transcript,
) -> Vec<F> {
    let mut eqs: Vec<Vec<<F as Field>::BaseField>> = vec![];
    for z in zs.iter() {
        let mut res = vec![F::BaseField::one()];
        for &b in z.iter().rev() {
            res = res
                .iter()
                .flat_map(|&prod| [prod * (F::BaseField::one() - b), prod * b])
                .collect();
        }
        eqs.push(res);
    }
    let r = transcript.challenge_fext::<F>();
    let mut eq = vec![];
    for i in 0..eqs[0].len() {
        let mut res = F::zero();
        for j in 0..eqs.len() {
            res = (res * r).add_base_elem(&eqs[j][i]);
        }
        eq.push(res);
    }
    let mut poly_evals = poly.evals;
    let var_num = poly.var_num;
    let mut new_point = vec![];
    for i in 0..var_num {
        let m = 1 << (var_num - i);
        let (sum_0, sum_1, sum_2) = (0..m).step_by(2).fold((F::zero(), F::zero(), F::zero()), |acc, x| {
            let p_0 = poly_evals[x];
            let p_1 = poly_evals[x + 1];
            let e_0 = eq[x];
            let e_1 = eq[x + 1];
            (
                acc.0 + p_0 * e_0,
                acc.1 + p_1 * e_1,
                acc.2 + (p_1 + p_1 - p_0) * (e_1 + e_1 - e_0),
            )
        });
        transcript.append_f(sum_0);
        transcript.append_f(sum_1);
        transcript.append_f(sum_2);
        let challenge = transcript.challenge_fext::<F>();
        new_point.push(challenge);
        sumcheck_next_domain(&mut poly_evals, m / 2, challenge);
        sumcheck_next_domain(&mut eq, m / 2, challenge);
    }
    new_point
}

fn sumcheck_next_domain<F: Field>(poly_evals: &mut Vec<F>, m: usize, challenge: F) {
    for j in 0..m {
        poly_evals[j] = poly_evals[j * 2] + (poly_evals[j * 2 + 1] - poly_evals[j * 2]) * challenge;
    }
}
