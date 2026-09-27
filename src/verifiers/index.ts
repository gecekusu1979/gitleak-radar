import { Finding } from "../types/index.js";
import { verifyGithubPat } from "./github.js";
import { verifySlackWebhook } from "./slack.js";
import { verifyStripeKey } from "./stripe.js";

type VerifierFunction = (secret: string) => Promise<boolean | null>;

const verifiers: Record<string, VerifierFunction> = {
    "github-pat": verifyGithubPat,
    "slack-webhook": verifySlackWebhook,
    "stripe-api-key": verifyStripeKey
};

export async function verifyFinding(finding: Finding, rawSecret: string): Promise<boolean | null> {
    const verifier = verifiers[finding.ruleId];
    if (!verifier) return null;

    try {
        return await verifier(rawSecret);
    } catch (err: any) {
        // If verifier throws network error etc, we return null (unknown)
        return null;
    }
}
