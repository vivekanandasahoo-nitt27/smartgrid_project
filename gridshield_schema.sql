--
-- PostgreSQL database dump
--

\restrict 9jMZhHfM2mWmiRBTdCzPPJjbfZx8S7dRNMQzOMGP483CpEM4LcPFbOMiClxxVjY

-- Dumped from database version 18.6
-- Dumped by pg_dump version 18.6

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: checkpoint_blobs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.checkpoint_blobs (
    thread_id text NOT NULL,
    checkpoint_ns text DEFAULT ''::text NOT NULL,
    channel text NOT NULL,
    version text NOT NULL,
    type text NOT NULL,
    blob bytea
);


--
-- Name: checkpoint_migrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.checkpoint_migrations (
    v integer NOT NULL
);


--
-- Name: checkpoint_writes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.checkpoint_writes (
    thread_id text NOT NULL,
    checkpoint_ns text DEFAULT ''::text NOT NULL,
    checkpoint_id text NOT NULL,
    task_id text NOT NULL,
    idx integer NOT NULL,
    channel text NOT NULL,
    type text,
    blob bytea NOT NULL,
    task_path text DEFAULT ''::text NOT NULL
);


--
-- Name: checkpoints; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.checkpoints (
    thread_id text NOT NULL,
    checkpoint_ns text DEFAULT ''::text NOT NULL,
    checkpoint_id text NOT NULL,
    parent_checkpoint_id text,
    type text,
    checkpoint jsonb NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL
);


--
-- Name: gridshield_attack_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.gridshield_attack_events (
    event_id text NOT NULL,
    measurements jsonb NOT NULL,
    attack_probability double precision NOT NULL,
    confidence_route text NOT NULL,
    status text NOT NULL,
    eligible_for_training boolean DEFAULT false NOT NULL,
    human_review_status text DEFAULT 'pending'::text NOT NULL,
    human_verified_attack boolean DEFAULT false NOT NULL,
    data_admission_status text DEFAULT 'pending'::text NOT NULL,
    verified_label smallint,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    eligibility_approved_at timestamp with time zone,
    CONSTRAINT gridshield_attack_events_attack_probability_check CHECK (((attack_probability >= (0)::double precision) AND (attack_probability <= (1)::double precision))),
    CONSTRAINT gridshield_attack_events_verified_label_check CHECK (((verified_label IS NULL) OR (verified_label = 1)))
);


--
-- Name: gridshield_samples; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.gridshield_samples (
    id bigint NOT NULL,
    measurements jsonb NOT NULL,
    label smallint NOT NULL,
    source_file text NOT NULL,
    dataset_role text NOT NULL,
    record_hash text NOT NULL,
    eligible_for_training boolean DEFAULT false NOT NULL,
    admission_status text DEFAULT 'initial_import'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT gridshield_samples_dataset_role_check CHECK ((dataset_role = ANY (ARRAY['training'::text, 'evaluation'::text]))),
    CONSTRAINT gridshield_samples_label_check CHECK ((label = ANY (ARRAY[0, 1, 2])))
);


--
-- Name: gridshield_samples_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

ALTER TABLE public.gridshield_samples ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.gridshield_samples_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: checkpoint_blobs checkpoint_blobs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.checkpoint_blobs
    ADD CONSTRAINT checkpoint_blobs_pkey PRIMARY KEY (thread_id, checkpoint_ns, channel, version);


--
-- Name: checkpoint_migrations checkpoint_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.checkpoint_migrations
    ADD CONSTRAINT checkpoint_migrations_pkey PRIMARY KEY (v);


--
-- Name: checkpoint_writes checkpoint_writes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.checkpoint_writes
    ADD CONSTRAINT checkpoint_writes_pkey PRIMARY KEY (thread_id, checkpoint_ns, checkpoint_id, task_id, idx);


--
-- Name: checkpoints checkpoints_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.checkpoints
    ADD CONSTRAINT checkpoints_pkey PRIMARY KEY (thread_id, checkpoint_ns, checkpoint_id);


--
-- Name: gridshield_attack_events gridshield_attack_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.gridshield_attack_events
    ADD CONSTRAINT gridshield_attack_events_pkey PRIMARY KEY (event_id);


--
-- Name: gridshield_samples gridshield_samples_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.gridshield_samples
    ADD CONSTRAINT gridshield_samples_pkey PRIMARY KEY (id);


--
-- Name: gridshield_samples gridshield_samples_record_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.gridshield_samples
    ADD CONSTRAINT gridshield_samples_record_hash_key UNIQUE (record_hash);


--
-- Name: checkpoint_blobs_thread_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX checkpoint_blobs_thread_id_idx ON public.checkpoint_blobs USING btree (thread_id);


--
-- Name: checkpoint_writes_thread_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX checkpoint_writes_thread_id_idx ON public.checkpoint_writes USING btree (thread_id);


--
-- Name: checkpoints_thread_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX checkpoints_thread_id_idx ON public.checkpoints USING btree (thread_id);


--
-- Name: idx_gridshield_attack_events_eligible; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_gridshield_attack_events_eligible ON public.gridshield_attack_events USING btree (eligible_for_training) WHERE (eligible_for_training = true);


--
-- Name: idx_gridshield_training_eligible; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_gridshield_training_eligible ON public.gridshield_samples USING btree (eligible_for_training) WHERE (dataset_role = 'training'::text);


--
-- PostgreSQL database dump complete
--

\unrestrict 9jMZhHfM2mWmiRBTdCzPPJjbfZx8S7dRNMQzOMGP483CpEM4LcPFbOMiClxxVjY

