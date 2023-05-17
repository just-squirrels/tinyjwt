import { createHmac } from "crypto";

type Header = {
    alg: "sha256";
    kid: string;
}

export type Claims<T = void> = {
    sub: string;
    exp: number;
    iss?: string;
    aud?: string;
    nbf?: number;
    iat?: number;
} & T;

const encode = (part: any) => Buffer.from(JSON.stringify(part)).toString("base64url");
const decode = (part: any) => JSON.parse(Buffer.from(part, "base64url").toString());

function gensig(header: string, content: string, key: string) {
    const hmac = createHmac("sha256", key);
    hmac.update(`${header}.${content}`);
    return hmac.digest("base64url");
}

export function sign<T>(claims: Claims<T>, key: string, keyId?: string) {
    const header = encode({ alg: "sha256", kid: keyId });
    const content = encode(claims);
    const signature = gensig(header, content, key);
    return `${header}.${content}.${signature}`;
}

export function verify<T>(jwt: string, getKey: (keyId?: string) => string) {
    const parts = jwt.split(".");
    const header = decode(parts[0]) as Header;
    const key = getKey(header.kid);
    if (!key) { return; }

    const signature = gensig(parts[0], parts[1], key);
    if (signature !== parts[2]) { return; }

    const content = decode(parts[1]) as Claims<T>;
    if (content.exp < Date.now()) { return; }
    if (content.nbf && content.nbf > Date.now()) { return; }

    return content;
}

export default { sign, verify };
