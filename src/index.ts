import { computeHmac, SupportedAlgorithm } from '@ethersproject/sha2';
import * as nacl from 'tweetnacl'

import { replaceDerive, pathRegex } from './utils';

interface Nacl {
    crypto_sign_seed_keypair: (
        val: Buffer,
    ) => { signPk: Buffer; signSk: Buffer };
}
type Hex = string;
type Path = string;

type Keys = {
    key: Buffer;
    chainCode: Buffer;
};

const ED25519_CURVE = 'ed25519 seed';
const HARDENED_OFFSET = 0x80000000;

export const getMasterKeyFromSeed = (seed: Hex): Keys => {
    const hmac = computeHmac(SupportedAlgorithm.sha512, Buffer.from(ED25519_CURVE), Buffer.from(seed, 'hex'));
    const minus0x = hmac.slice(2);
    const IL = minus0x.slice(0, 64);
    const IR = minus0x.slice(64);
    return {
        key: Buffer.from(IL, 'hex'),
        chainCode: Buffer.from(IR, 'hex'),
    };
};

const CKDPriv = ({ key, chainCode }: Keys, index: number): Keys => {
    const indexBuffer = Buffer.allocUnsafe(4);
    indexBuffer.writeUInt32BE(index, 0);

    const data = Buffer.concat([Buffer.alloc(1, 0), key, indexBuffer]);

    const hmac = computeHmac(SupportedAlgorithm.sha512, chainCode, data);
    const minus0x = hmac.slice(2);
    const IL = minus0x.slice(0, 64);
    const IR = minus0x.slice(64);
    return {
        key: Buffer.from(IL, 'hex'),
        chainCode: Buffer.from(IR, 'hex'),
    };
};

export const getPublicKey = (privateKey: Buffer, withZeroByte = true): Buffer => {
    const keyPair = nacl.sign.keyPair.fromSeed(privateKey);
    const signPk = keyPair.secretKey.subarray(32);
    const zero = Buffer.alloc(1, 0);
    return withZeroByte ?
        Buffer.concat([zero, Buffer.from(signPk)]) :
        Buffer.from(signPk);
};

export const isValidPath = (path: string): boolean => {
    if (!pathRegex.test(path)) {
        return false;
    }
    return !path
        .split('/')
        .slice(1)
        .map(replaceDerive)
        .some(isNaN as any /* ts T_T*/);
};

export const derivePath = (path: Path, seed: Hex, offset = HARDENED_OFFSET): Keys => {
    if (!isValidPath(path)) {
        throw new Error('Invalid derivation path');
    }

    const { key, chainCode } = getMasterKeyFromSeed(seed);
    const segments = path
        .split('/')
        .slice(1)
        .map(replaceDerive)
        .map(el => parseInt(el, 10));

    return segments.reduce(
        (parentKeys, segment) => CKDPriv(parentKeys, segment + offset),
        { key, chainCode },
    );
};
