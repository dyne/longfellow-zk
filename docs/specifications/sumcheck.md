---
title: Sumcheck specification
description: Layered circuits, polynomial claims, transcript encryption, and verifier constraints.
outline: deep
---

# Sumcheck specification

::: info Source mirror
Mirrored from `vendor/longfellow-zk/docs/specs/sumcheck.md` at the upstream
revision pinned by this repository. See the [specifications map](index.md) for
status and provenance.
:::

## Special conventions for sumcheck arrays

The square brackets `A[j]` denote generic array indexing.

For the arrays of field elements used in the sumcheck protocol,
however, it is convenient to use the conventions that follow.

The sumcheck array `A[i]` is implicitly assumed to be defined for all
nonnegative integers `i`, padding with zeroes as necessary.  Here,
"zero" is well defined because `A[]` is an array of field elements.

Arrays can be multi-dimensional, as in the three-dimensional array
`Q[g, l, r]`.  It is understood that the array is padded with
infinitely many zeroes in each dimension.

Depending on the context, some arrays may consist of almost all non-zero
values, while other arrays may be sparse, containing very few non-zero
values (ignoring the zero-padding convention above). Implementations
should use dense or sparse representations of arrays as appropriate.

Given array `A[]` and field element `x`, the function
`bind(A, x)` returns the array `B` such that
```
  B[i] = (1 - x) * A[2 * i] + x * A[2 * i + 1]
```

In case of multiple dimensions such as `Q[g, l, r]`,
always bind across the first dimension.  For example,

```
  bind(Q, x)[g, l, r] =
     (1 - x) * Q[2 * g, l, r] + x * Q[2 * g + 1, l, r]
```

This `bind` can be generalized to an array of field elements as follows:
```
  bindv(A, X) =
       A                                  if X is empty
       bindv(bind(A, X[0]), X[1..])       otherwise
```

Two-dimentional arrays can be transposed in the usual way:
```
  transpose(Q)[l, r] = Q[r, l] .
```

## The `EQ[]` array

`EQ_{n}[i, j]` is a special 2D array defined as

```
   EQ_{n}[i, j] = 1   if i = j and i < n
                  0   otherwise
```

The sumcheck literature usually assumes that `n` is a power of 2,
but this document allows `n` to be an arbitrary integer.  When `n` is clear from
context or unimportant, the subscript is omitted like
`EQ[i, j]`.

`EQ[]` is important because the general expansion
```
   V[i] = SUM_{j} EQ[i, j] V[j]
```
commutes with binding, yielding
```
   bindv(V, X) = SUM_{j} bindv(EQ, X)[j] V[j] .
```
That is, one way to compute `bindv(V, X)` is via
dot product of `V` with `bindv(EQ, X)`.  This strategy
may or may not be advantageous in practice, but it
becomes mandatory when `bindv(V, X)` must be computed
via a commitment scheme that supports linear
constraints but not binding.

This document only uses bindings of `EQ` and never `EQ` itself,
and therefore the whole array never needs to be stored explicitly.
For `n = 2^l` and `X` of size `l`, `bindv(EQ_{n}, X)` can be computed
recursively in linear time as follows.

``` python
def bindeq(
        field: FiniteField,
        challenges: list[FiniteRingElement],
        ) -> list[FiniteRingElement]:
    log_n = len(challenges)
    if log_n == 0:
        return [field.one()]
    n = 2 ** log_n
    b = [field.zero() for _ in range(n)]
    a = bindeq(field, challenges[1:])
    for i in range(n // 2):
        b[2 * i] = (field.one() - challenges[0]) * a[i]
        b[2 * i + 1] = challenges[0] * a[i]
    return b
```

For `m <= n`, `bindv(EQ_{n}, X)[i]` and `bindv(EQ_{m}, X)[i]`
agree for `0 <= i < m`, and thus
`bindv(EQ_{m}, X)[i]` can be computed by padding `m` to the next power of 2
and ignoring the extra elements.
With some care, it is possible to compute `bindeq()`
in-place on a single array of arbitrary size `m` and eliminate
the recursion completely.

### Remark
Let `m <= n`, `A = bindv(EQ_{m}, X)` and `B = bindv(EQ_{n}, X)`.  It
is true that `A[i] = B[i]` for `i < m`.  However, it is also true that `A[i] =
0` for `i >= m`, whereas `B[i]` is in general nonzero.  Thus, care
must be taken when computing a further binding `bindv(A, Y)`,
which is in general not the same as `bindv(B, Y)`.  A second binding is
not needed in this document,  but certain closed-form expressions for
the binding found in the literature agree with these definitions only
when `m` is a power of 2.

## Circuits

### Layered circuits
A circuit consists of `NL` *layers*.  By convention, layer `j`
computes wires `V[j]` given wires `V[j + 1]`, where each `V[j]` is an
array of field elements.  A *wire* is an element `V[j][w]` for some `j`
and `w`.  Thus, `V[0]` denotes the output wires of the entire circuit,
and `V[NL]` denotes the input wires.

A circuit is intended to check that some property of the input holds,
and by convention, the check is considered successful if all output
wires are 0, that is, if `V[0][w] = 0` for all `w`.

### Quad representation
The computation of circuit is defined by a set of *quads* `Q[j]`, one
per layer.  Given the output of layer `j + 1`, the output of of layer
`j` is given by the following equation:

```
  V[j][g] = SUM_{l, r} Q[j][g, l, r] V[j + 1][l] V[j + 1][r] .
```

The quad `Q[j][]` is thus a three-dimensional array in the indices `g`,
`l`, and `r` where `0 <= g < NW[j]` and `0 <= l, r < NW[j + 1]`.  In
practice, `Q[j][]` is sparse.

The specification of the circuit contains an auxiliary
vector of quantities `LV[j]` with the property that `V[j][w] = 0`
for all `w >= 2^{LV[j]}`.  Informally, `LV[j]` is the number
of bits needed to name a wire at layer `j`, but `LV[j]` may
be larger than the minimum required value.

### In-circuit assertions
In the libzk system, a theorem is represented by a circuit such that
the theorem is true if and only if all outputs of the circuit are
zero.  It happens in practice that many output wires are computed early
in the circuit (i.e., in a layer closer to the input), but because of
layering, they need to be copied all the way to output layer in order
to be compared against zero.  This copy seems to introduce large
overheads in practice.

A special convention can mitigate this problem.  Abstractly,
a layer is represented by *two* quads `Q` and `Z`, and the
operation of the layer is described by the two equations

```
  V[j][g] = SUM_{l, r} Q[j][g, l, r] V[j + 1][l] V[j + 1][r]
       0  = SUM_{l, r} Z[j][g, l, r] V[j + 1][l] V[j + 1][r]
```

Thus, the `Z` quad asserts that, for given layer `j`
and output wire `g`, a certain quadratic combination of
the input wires is zero.

The actual protocol verifies a random linear combination
of those two equations, effectively operating on a combined
quad `QZ = Q + beta * Z` for some random `beta`.

To allow for a compact representation of the two quads without
losing any real generality, the following conditions are imposed:

* The two quads `Q` and `Z` are disjoint: for all layers `j` and output
  wire `g`, if any `Q[j][g, ., .]` are nonzero, then all `Z[j][g, ., .]`
  are zero, and vice versa.
* `Z` is binary: `Z[j][g, l, r] \in {0, 1}`

With these choices, the two quads allow a compact sparse
representation as a single list of 4-tuples `(g, l, r, v)`
with the following conventions:

* If `v = 0`, the 4-tuple represents an element of `Z`,
  and `Z[j][g, l, r] = 1`.
* If `v != 0`, the 4-tuple represents an element of `Q`,
  and `Q[j][g, l, r] = v`.
* All other elements of `Q` and `Z` not specified by the list are
  zero.

Moreover, this compact representation can be transformed into
a representation of `QZ = Q + beta * Z` by replacing all `v = 0`
with `v = beta`.

## Representation of polynomials
In a generic sumcheck protocol, the prover sends to the verifier
polynomials of a degree specified in advance.  In the present document,
the polynomials are always of degree two, and are represented by their
evaluations at three points `P0 = 0`, `P1 = 1`, and `P2`, where `0`
and `1` are the additive and multiplicative identities in the field.
The choice of `P2` depends upon the field.  For fields of characteristic
greater than 2, set `P2 = 2` (= `1 + 1` in the field).  For `GF(2^128)`
expressed as `GF(2)[X] / (X^128 + X^7 + X^2 + X + 1)`, set `P2 = inj(2)`
as defined in (#gf2k).  This document does not prescribe a choice of
P2 for binary fields other than `GF(2^128)`.

At the start of each round of communication in a sumcheck protocol, both the
prover and the (virtual) sumcheck verifier agree on a claim value, which
represents the sum of the evaluation of some function at all inputs `{0,1}^*`.
The polynomials computed by the prover represent the sum of the
evaluations of the multilinear extension of that same function, with one
argument fixed to `P0`, `P1`, or `P2`, and all other arguments chosen
from `{0,1}`.
Therefore, the sum of `p(P0) + p(P1)` is equal to the claim from the
start of the sumcheck round, and the prover only needs to send two field
elements in order for the parties to agree on the entire degree two
polynomial.
Here, `p(P0)` and `p(P2)` are sent to the (virtual) sumcheck verifier,
and `p(P1)` is reconstructed from `p(P0)` and the claim.

## Transcript encryption and deferred verification

The sumcheck protocol produces a series of polynomials and claim values,
computed from the circuit input values, to prove that the circuit
was evaluated correctly.
As described in (#overview), these polynomials and claims are not
directly revealed to the verifier.
Rather, the field elements that make up these values are encrypted with
a one-time pad by subtracting a randomly chosen pad value from each
field element, and the difference is sent to the verifier.

When the verifier executes the sumcheck protocol, it does not have
direct access to all the circuit inputs, and it is only given the
one-time pad encrypted forms of the sumcheck polynomials and per-layer
claims, not the corresponding plaintext values.
Therefore, the prover and verifier defer part of the verification by
producing a series of linear and quadratic constraints, relating the
private input values and the one-time pad values, so that those
constraints can be checked with the Ligero zero-knowledge system (see
(#ligero-zk-proof)).

The variables used in these constraints are assigned sequentially, first
to the private circuit inputs, then to elements of the one-time pad.
Variables for one-time pad values are assigned to values for circuit
layers in order, starting with the output layer. Within each layer,
variables are first assigned to one-time pad values for sumcheck
polynomials, then to the per-layer claim values. The number of sumcheck
polynomials for each layer is equal to double the value of
`log_num_input_wires` for that layer of the circuit.
The polynomials are represented by two field
elements each, one for the evaluation at `P0 = 0`, and one for the
evaluation at `P2`. At the end of the variables for each layer, three
variables are assigned for claim-related values. Two variables are used
for the one-time pad values for the claims `vl` and `vr`. Then, a
variable is used for the product of those two one-time pad values.

``` python
def construct_symbolic_variables(
        field: FiniteField,
        circuit: Circuit,
        ) -> tuple[
            tuple[MPolynomial, ...],
            list[LayerPad[MPolynomial]],
        ]:
    num_private_inputs = circuit.ninputs - circuit.pub_in
    witness_length = (
        num_private_inputs
        + sum(l.log_num_input_wires for l in circuit.layers) * 4
        + len(circuit.layers) * 3
    )
    ring = PolynomialRing(field, witness_length, "w")
    variables = ring.gens()
    witness_variables = variables[:num_private_inputs]
    pad_variables = variables[num_private_inputs:]
    return (
        witness_variables,
        construct_symbolic_pad(field, circuit, pad_variables)
    )


def construct_symbolic_pad(
        field: FiniteField,
        circuit: Circuit,
        variables: Sequence[MPolynomial],
        ) -> list[LayerPad[MPolynomial]]:
    it = iter(variables)
    layers = []
    for layer in circuit.layers:
        evals: list[list[SumcheckPolynomial[MPolynomial]]] = []
        for round in range(layer.log_num_input_wires):
            evals.append([])
            for _ in range(2):
                evals[round].append(
                    SumcheckPolynomial(
                        next(it),
                        next(it),
                    ),
                )
        vl = next(it)
        vr = next(it)
        vl_vr = next(it)
        layers.append(LayerPad(
            evals,
            vl,
            vr,
            vl_vr,
        ))
    return layers


def construct_concrete_pad(
        field: FiniteField,
        circuit: Circuit,
        pad_prg: Callable[
            [FiniteField],
            FiniteRingElement,
        ] = random_element,
        ) -> tuple[
            list[LayerPad[FiniteRingElement]],
            list[FiniteRingElement],
        ]:
    """
    Chooses one-time pad values, and returns them in structured and
    flattened forms.
    """
    layers = []
    flattened = []
    for layer in circuit.layers:
        evals: list[list[SumcheckPolynomial[FiniteRingElement]]] = []
        for round in range(layer.log_num_input_wires):
            evals.append([])
            for _ in range(2):
                p0 = pad_prg(field)
                p2 = pad_prg(field)
                evals[round].append(SumcheckPolynomial(p0, p2))
                flattened.append(p0)
                flattened.append(p2)
        vl = pad_prg(field)
        vr = pad_prg(field)
        vl_vr = vl * vr
        layers.append(LayerPad(
            evals,
            vl,
            vr,
            vl_vr,
        ))
        flattened.append(vl)
        flattened.append(vr)
        flattened.append(vl_vr)
    return (layers, flattened)
```

## Transform circuit and wires into a padded proof

The prover constructs a padded proof by executing the sumcheck protocol
in order to certify that the wires at each layer of the circuit are
correctly calculated from the wires at the preceding layer.

The goal is to prove that, for some layer index `j`, and every output
wire index `g` in that layer, the following all hold with high
probability.

```
V[j][g] = SUM_{l, r} Q[j][g, l, r] V[j + 1][l] V[j + 1][r]

0 = SUM_{l, r} Z[j][g, l, r] V[j + 1][l] V[j + 1][r]
```

These equations are combined into one equation after multiplying them by
random verifier challenges. This equation is of the form

```
claim = SUM_{l, r} QUAD[j][l, r] V[j + 1][l] V[j + 1][r]
```

If we reinterpret the wire indices `l` and `r` as binary numbers,
replacing them both with `log_num_input_wires` many variables having
value 0 or 1, then this equation has the form needed to apply the
sumcheck protocol.

At each layer, both parties start with two claims that each represent a
linear combination of the layer's output wire values.
Concretely, the claims for the layer's outputs are `bind(V[j], G[0])`
and `bind(V[j], G[1])` where `G[0]` and `G[1]` are arrays of verifier
challenges.
These two claim values get combined into one using a random challenge
value.
In each successive round of communication, the function inside the
summation is replaced with a new function having one fewer parameter,
one of the output wire arrays is halved in size by binding it with a
random challenge, and the claim value is replaced with a newly computed
claim value.
The prover proves that the new claim values and the new function at each
round are consistent with those in the previous round by evaluating the
multilinear extension of the function at multiple points, including
points with a random challenge coordinate.
The prover computes a degree two polynomial by summing this multilinear
extension at many points, with the polynomial's parameter determining
the last parameter of the multilinear extension.
Two evaluations of this polynomial are sent to the verifier, though as
noted above these evaluations get encrypted with a one-time pad.
After several rounds of communication, the function being summed is
replaced with a constant, and both output wire arrays are replaced with
two new claim values.
Concretely, the new claims will be `bind(V[j + 1], G'[0])` and `bind(V[j
+ 1], G'[0])`, where `V[j + 1]` is the input wires of layer j, and
`G'[0]` and `G'[1]` are a fresh set of verifier challenges, chosen at
each round of the sumcheck protocol.
These two claim values are encrypted with a one-time pad and sent to the
verifier.

Before the first round, a fixed number of verifier challenges are
generated and discarded. These are reserved for possible future
extensions to the protocol. Additionally, a fixed number of challenges
are generated for binding the output wires before the first round, with
the remainder of the challenges being discarded. In both of these cases,
`MAX_BINDINGS = 40` challenges are generated. For all subsequent layers,
challenges used for binding output wires are generated one at a time,
with no extra unused challenges.

``` python
def sumcheck_circuit(
        field: FiniteField,
        circuit: Circuit,
        wires: list[list[FiniteRingElement]],
        pad: list[LayerPad[FiniteRingElement]],
        transcript: Transcript) -> list[LayerProof]:
    for _ in range(MAX_BINDINGS):
        # Discard initial challenges. These are reserved for possible
        # future use.
        _ = transcript.generate_field(field)
    challenges = [
        transcript.generate_field(field)
        for _ in range(MAX_BINDINGS)
    ]
    G = (
        challenges[:circuit.log_num_outputs],
        challenges[:circuit.log_num_outputs],
    )
    proof: list[LayerProof] = []
    for j, layer in enumerate(circuit.layers):
        alpha = transcript.generate_field(field)

        # Form the combined quad, QZ = Q + beta * Z, to handle
        # in-circuit assertions.
        beta = transcript.generate_field(field)
        QZ = layer.quad + beta * layer.Z

        # QZ is three-dimensional, QZ[g, l, r].
        QUAD = QZ.bindv(G[0]) + alpha * QZ.bindv(G[1])
        # Having bound g, QUAD is now effectively two-dimensional,
        # QUAD[l, r].
        QUAD = QUAD.drop_dimension()

        layer_proof, G = sumcheck_layer(
            field,
            QUAD,
            wires[j + 1],
            layer.log_num_input_wires,
            pad[j],
            transcript,
        )
        proof.append(layer_proof)
    return proof
```

``` python
def sumcheck_layer(
        field: FiniteField,
        QUAD: SparseArray,
        wires: list[FiniteRingElement],
        log_num_input_wires: int,
        layer_pad: LayerPad[FiniteRingElement],
        transcript: Transcript) -> tuple[
            LayerProof,
            tuple[list[FiniteRingElement], list[FiniteRingElement]],
        ]:
    VL = DenseArray(field, wires)
    VR = DenseArray(field, wires)
    P2 = sumcheck_p2(field)
    evals: list[list[SumcheckPolynomial[FiniteRingElement]]] = []
    G: tuple[list, list] = ([], [])
    for round in range(log_num_input_wires):
        evals.append([])
        for hand in range(2):
            # Consider the following polynomial.
            #
            # p(x) = \sum_{l, r} bind(QUAD, x)[l, r]
            #                    * bind(VL, x)[l]
            #                    * VR[r]
            #
            # We evaluate this polynomial at the points P0 and P2.
            # The sum of p(P0) and p(P1) is implicitly known already,
            # so p(P1) does not need to be calculated.
            #
            # Implementation note: this can be computed more
            # efficiently by first computing the intermediate array
            # defined as follows:
            #
            # A[l] = \sum_{r} QUAD[l, r] * VR[r]
            #
            # This allows performing only one pass over the quad, and
            # binding only 1-D arrays with length equal to the number
            # of wires.
            eval_p0 = sum(
                (
                    v * VL[k[hand]] * VR[k[1 - hand]]
                    for (k, v) in QUAD.entries.items()
                    if k[hand] & 1 == 0
                ),
                start=field.zero(),
            )
            QUAD_bind_p2 = QUAD.bind(P2, axis=hand)
            VL_bind_p2 = VL.bind(P2)
            eval_p2 = field.zero()
            for (k, v) in QUAD_bind_p2.entries.items():
                eval_p2 += v * VL_bind_p2[k[hand]] * VR[k[1 - hand]]
            blinded_p0 = eval_p0 - layer_pad.evals[round][hand].p0
            blinded_p2 = eval_p2 - layer_pad.evals[round][hand].p2
            evals[round].append(SumcheckPolynomial(
                blinded_p0,
                blinded_p2,
            ))
            transcript.write_field(blinded_p0)
            transcript.write_field(blinded_p2)
            challenge = transcript.generate_field(field)
            G[hand].append(challenge)

            # Bind the current index variable to the challenge.
            VL = VL.bind(challenge)
            QUAD = QUAD.bind(challenge, axis=hand)

            # Swap VL and VR.
            (VL, VR) = (VR, VL)

    layer_proof = LayerProof(
        evals,
        VL[0] - layer_pad.vl,
        VR[0] - layer_pad.vr,
    )
    transcript.write_field_element_array([
        layer_proof.vl,
        layer_proof.vr,
    ])
    return (layer_proof, G)
```

## Generate constraints from the public inputs and the padded proof

This section defines a procedure `constraints_circuit` for transforming
the proof returned by `sumcheck_circuit` into constraints to be checked
by the commitment scheme.  Specifically, each layer produces one linear
constraint and one quadratic constraint. One additional linear
constraint is added after processing the input layer.

The main difficulty in describing the algorithm is that it operates
not on concrete witnesses, but on expressions in which the witnesses
are symbolic quantities.  Symbolic manipulation is necessary because
the verifier does not have access to the witnesses.  To avoid
overspecifying the exact representation of such symbolic expressions,
the convention is that the prefix `sym_` indicates not a concrete
value, but a symbolic representation of the value.  Thus, `w[3]` is
the fourth concrete witness in the `w` array, and `sym_w[3]` is a
symbolic representation of the fourth element in the `w` array.  The
algorithm does not need arbitrarily complex symbolic expressions.  It
suffices to keep track of affine symbolic expressions of the form
`k + SUM_{i} a[i] sym_w[i]` for some (concrete, nonsymbolic) field elements
`k` and `a[]`.

``` python
def constraints_circuit(
        field: FiniteField,
        circuit: Circuit,
        public_inputs: list[FiniteRingElement],
        sym_private_inputs: Sequence[MPolynomial],
        sym_pad: list[LayerPad[MPolynomial]],
        transcript: Transcript,
        proof: list[LayerProof]) -> tuple[
            list[MPolynomial],
            list[QuadraticConstraint],
        ]:
    """
    Processes a sumcheck proof, and produces lists of constraints for
    verification.

    Linear constrants are returned as expressions of the form
    `k + SUM_{i} a[i] sym_w[i]`, representing
    `k + SUM_{i} a[i] sym_w[i] = 0`, and quadratic constraints are
    returned as objects holding three variables, representing
    `w_x * w_y = w_z`.
    """
    for _ in range(MAX_BINDINGS):
        # Discard initial challenges. These are reserved for possible
        # future use.
        _ = transcript.generate_field(field)
    challenges = [
        transcript.generate_field(field)
        for _ in range(MAX_BINDINGS)
    ]
    G = (
        challenges[:circuit.log_num_outputs],
        challenges[:circuit.log_num_outputs],
    )
    linear_constraints = []
    quadratic_constraints = []
    claim_0: MPolynomial | FiniteRingElement
    claim_1: MPolynomial | FiniteRingElement
    for j, layer in enumerate(circuit.layers):
        alpha = transcript.generate_field(field)
        beta = transcript.generate_field(field)
        QZ = layer.quad + beta * layer.Z
        QUAD = QZ.bindv(G[0]) + alpha * QZ.bindv(G[1])
        QUAD = QUAD.drop_dimension()
        if j == 0:
            claim_0 = field.zero()
            claim_1 = field.zero()
        else:
            claim_0 = claim_0 + sym_pad[j - 1].vl
            claim_1 = claim_1 + sym_pad[j - 1].vr
        (
            G,
            (claim_0, claim_1),
            linear_constraint,
            quadratic_constraint,
        ) = constraints_layer(
            field,
            QUAD,
            layer.log_num_input_wires,
            sym_pad[j],
            transcript,
            proof[j],
            (claim_0, claim_1),
            alpha,
        )
        linear_constraints.append(linear_constraint)
        quadratic_constraints.append(quadratic_constraint)

    # Add a constraint checking that the two final claims equal the
    # binding of sym_inputs with G[0] and G[1].
    gamma = transcript.generate_field(field)
    # eq2 = bindv(EQ, G[0]) + gamma * bindv(EQ, G[1])
    eq2 = [
        a + gamma * b
        for a, b in zip(
            bindeq(field, G[0]),
            bindeq(field, G[1]),
        )
    ]
    sym_layer_pad = sym_pad[-1]
    num_private_inputs = circuit.ninputs - circuit.pub_in
    final_constraint = (
        sum(
            (
                eq2[i] * public_inputs[i]
                for i in range(circuit.pub_in)
            ),
            start=field.zero(),
        )
        + sum(
            (
                eq2[i + circuit.pub_in] * sym_private_inputs[i]
                for i in range(num_private_inputs)
            ),
            start=field.zero(),
        )
        - claim_0
        - sym_layer_pad.vl
        - gamma * claim_1
        - gamma * sym_layer_pad.vr
    )
    linear_constraints.append(final_constraint)
    return linear_constraints, quadratic_constraints
```

``` python
def constraints_layer(
        field: FiniteField,
        QUAD: SparseArray,
        log_num_input_wires: int,
        sym_layer_pad: LayerPad[MPolynomial],
        transcript: Transcript,
        layer_proof: LayerProof,
        claims: tuple[
            MPolynomial | FiniteRingElement,
            MPolynomial | FiniteRingElement,
        ],
        alpha: FiniteRingElement) -> tuple[
            tuple[list[FiniteRingElement], list[FiniteRingElement]],
            tuple[FiniteRingElement, FiniteRingElement],
            MPolynomial,
            QuadraticConstraint,
        ]:
    # Initial claim. This is a known constant during the first round,
    # but it will be a symbolic affine expression in subsequent
    # rounds.
    sym_claim = claims[0] + alpha * claims[1]

    # Lagrange basis polynomials
    R = field["x"]
    lag_0 = R.lagrange_polynomial([
        (field.zero(), field.one()),
        (field.one(), field.zero()),
        (sumcheck_p2(field), field.zero()),
    ])
    lag_1 = R.lagrange_polynomial([
        (field.zero(), field.zero()),
        (field.one(), field.one()),
        (sumcheck_p2(field), field.zero()),
    ])
    lag_2 = R.lagrange_polynomial([
        (field.zero(), field.zero()),
        (field.one(), field.zero()),
        (sumcheck_p2(field), field.one()),
    ])

    G: tuple[list[FiniteRingElement], list[FiniteRingElement]] = (
        [],
        [],
    )
    for round in range(log_num_input_wires):
        for hand in range(2):
            hp = layer_proof.evals[round][hand]
            sym_hpad = sym_layer_pad.evals[round][hand]

            transcript.write_field(hp.p0)
            transcript.write_field(hp.p2)
            challenge = transcript.generate_field(field)
            G[hand].append(challenge)

            # After decrypting, the polynomial evaluations are
            # expected to be:
            #
            #   p(P0) = hp.p0 + sym_hpad.p0
            #   p(P2) = hp.p2 + sym_hpad.p2
            sym_p0 = hp.p0 + sym_hpad.p0
            sym_p2 = hp.p2 + sym_hpad.p2

            # Compute the implied evaluation, p(P1) = claim - p(P0),
            # in symbolic form.
            sym_p1 = sym_claim - sym_p0

            # Given p(P0), p(P1), and p(P2), interpolate the new
            # claim symbolically.
            sym_claim = (
                lag_0(challenge) * sym_p0
                + lag_1(challenge) * sym_p1
                + lag_2(challenge) * sym_p2
            )

            QUAD = QUAD.bind(challenge, axis=hand)

    # Now the bound QUAD is a 1x1 array.
    Q = QUAD.drop_dimension().drop_dimension()[()]

    # We want to verify that
    #
    #   sym_claim = Q * VL * VR
    #
    # where VL = layer_proof.vl + sym_layer_pad.vl
    #   and VR = layer_proof.vr + sym_layer_pad.vr
    #
    # To keep this constraint linear, we expand the multiplication,
    # and replace sym_layer_pad.vl * sym_layer_pad.vr with
    # sym_layer_pad.vl_vr, checking that these quantities are equal
    # in a separate quadratic constraint.

    linear_constraint = (
        sym_claim - Q * (
            layer_proof.vl * layer_proof.vr
            + layer_proof.vr * sym_layer_pad.vl
            + layer_proof.vl * sym_layer_pad.vr
            + sym_layer_pad.vl_vr
        )
    )
    quadratic_constraint = QuadraticConstraint(
        sym_layer_pad.vl,
        sym_layer_pad.vr,
        sym_layer_pad.vl_vr,
    )

    transcript.write_field_element_array([
        layer_proof.vl,
        layer_proof.vr,
    ])

    return (
        G,
        (layer_proof.vl, layer_proof.vr),
        linear_constraint,
        quadratic_constraint,
    )
```
