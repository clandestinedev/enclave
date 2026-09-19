CREATE TABLE "relationship_epochs" (
	"id" text PRIMARY KEY NOT NULL,
	"relationship_id" text NOT NULL,
	"epoch" integer NOT NULL,
	"epoch_nonce" text NOT NULL,
	"rotation_cause" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "relationships" (
	"id" text PRIMARY KEY NOT NULL,
	"user_a" text NOT NULL,
	"user_b" text NOT NULL,
	"initiator_user_id" text NOT NULL,
	"state" text DEFAULT 'PENDING' NOT NULL,
	"epoch" integer NOT NULL,
	"epoch_nonce" text NOT NULL,
	"offer_record" text,
	"transcript" text,
	"offer_consent" text,
	"accept_consent" text,
	"confirm_consent" text,
	"sas_proof_a" text,
	"sas_proof_b" text,
	"rka_public_a" text NOT NULL,
	"rka_public_b" text,
	"expires_at" timestamp with time zone NOT NULL,
	"established_at" timestamp with time zone,
	"terminated_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "devices" ADD COLUMN "cert_signature" text;--> statement-breakpoint
ALTER TABLE "devices" ADD COLUMN "cert_version" integer;--> statement-breakpoint
ALTER TABLE "relationship_epochs" ADD CONSTRAINT "relationship_epochs_relationship_id_relationships_id_fk" FOREIGN KEY ("relationship_id") REFERENCES "public"."relationships"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "relationships" ADD CONSTRAINT "relationships_user_a_users_id_fk" FOREIGN KEY ("user_a") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "relationships" ADD CONSTRAINT "relationships_user_b_users_id_fk" FOREIGN KEY ("user_b") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "relationships" ADD CONSTRAINT "relationships_initiator_user_id_users_id_fk" FOREIGN KEY ("initiator_user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
-- One active relationship per user pole (ADR 0004 §6 rule 1). Enforced at the
-- DB so concurrent offers/accepts have exactly one winner. Management by hand
-- (not in the drizzle schema) so drizzle-kit generation does not fight the
-- partial predicates.
CREATE UNIQUE INDEX "relationships_one_active_pair_idx" ON "relationships" (
    least("user_a", "user_b"),
    greatest("user_a", "user_b")
) WHERE "state" IN ('PENDING', 'ACCEPTED', 'ESTABLISHED');--> statement-breakpoint
CREATE UNIQUE INDEX "relationships_one_active_a_idx" ON "relationships" ("user_a")
    WHERE "state" IN ('PENDING', 'ACCEPTED', 'ESTABLISHED');--> statement-breakpoint
CREATE UNIQUE INDEX "relationships_one_active_b_idx" ON "relationships" ("user_b")
    WHERE "state" IN ('PENDING', 'ACCEPTED', 'ESTABLISHED');--> statement-breakpoint
CREATE UNIQUE INDEX "relationship_epochs_pair_epoch_idx" ON "relationship_epochs" ("relationship_id", "epoch");