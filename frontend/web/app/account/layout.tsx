"use client";
import type {ReactNode} from "react";import {PrewiseShell} from "@/components/PrewiseUI";
import mobileStyles from "../mobile-pages.module.css";
export default function AccountLayout({children}:{children:ReactNode}){return <PrewiseShell><main id="main-content" className={`account-shell account-preview ${mobileStyles.accountShell}`}><section className="account-content">{children}</section></main></PrewiseShell>}

