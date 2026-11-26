import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY as string);

export const publicConfig = {
  publishable: process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE,
  NEXT_PUBLIC_STRIPE_SECRET: "sk_live_51HdemoONLY0000",
};

export async function createIntent(amount: number) {
  return stripe.paymentIntents.create({ amount, currency: "usd" });
}
