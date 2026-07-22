"use client";

import { Menu, ShieldCheck, X } from "lucide-react";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";

import type { Session } from "@/lib/types";

export interface NavigationBarProps {
    currentPath: string;
    session: Session | null;
    onOpenAuth: (mode: "login" | "register") => void;
    onLogout: () => void;
}

const NAV_LINKS = [
    { label: "Trang chủ", href: "/" },
    { label: "Phân tích", href: "/analyze" },
    { label: "Chat AI", href: "/chat" },
    { label: "Giới thiệu", href: "/about" },
    { label: "Gói dịch vụ", href: "/pricing" },
];

function isActive(href: string, currentPath: string): boolean {
    return href === "/"
        ? currentPath === "/"
        : currentPath === href || currentPath.startsWith(`${href}/`);
}

function getInitials(displayName: string): string {
    const parts = displayName.trim().split(/\s+/).filter(Boolean);
    if (parts.length === 0) return "?";
    if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
    return `${parts[0][0]}${parts[parts.length - 1][0]}`.toUpperCase();
}

export default function NavigationBar({
    currentPath,
    session,
    onOpenAuth,
    onLogout,
}: NavigationBarProps): JSX.Element {
    const [mobileOpen, setMobileOpen] = useState(false);
    const [accountOpen, setAccountOpen] = useState(false);
    const accountRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        setMobileOpen(false);
        setAccountOpen(false);
    }, [currentPath]);

    useEffect(() => {
        function handleClickOutside(event: MouseEvent): void {
            if (accountRef.current && !accountRef.current.contains(event.target as Node)) {
                setAccountOpen(false);
            }
        }
        document.addEventListener("mousedown", handleClickOutside);
        return () => document.removeEventListener("mousedown", handleClickOutside);
    }, []);

    const links = NAV_LINKS.map((link) => {
        const active = isActive(link.href, currentPath);
        return (
            <li key={link.href}>
                <Link
                    href={link.href}
                    aria-current={active ? "page" : undefined}
                    className={`block rounded-md px-3 py-2 text-sm font-medium transition-colors ${
                        active
                            ? "bg-neutral-900 text-white"
                            : "text-neutral-600 hover:bg-neutral-100 hover:text-neutral-950"
                    }`}
                >
                    {link.label}
                </Link>
            </li>
        );
    });

    return (
        <header className="sticky top-0 z-40 w-full border-b border-neutral-200 bg-white/95 backdrop-blur">
            <nav className="mx-auto flex h-16 max-w-7xl items-center gap-4 px-4 sm:px-6 lg:px-8" aria-label="Điều hướng chính">
                <Link href="/" className="flex min-w-0 items-center gap-2.5 text-neutral-950">
                    <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-neutral-950 text-white">
                        <ShieldCheck className="h-5 w-5" aria-hidden="true" />
                    </span>
                    <span className="truncate text-sm font-bold sm:text-base">Prewise</span>
                </Link>

                <ul className="ml-auto hidden items-center gap-1 lg:flex">{links}</ul>

                <div className="ml-auto hidden items-center gap-2 sm:flex lg:ml-2">
                    {session === null ? (
                        <>
                            <button type="button" onClick={() => onOpenAuth("login")} className="rounded-md px-3 py-2 text-sm font-medium text-neutral-700 hover:bg-neutral-100">
                                Đăng nhập
                            </button>
                            <button type="button" onClick={() => onOpenAuth("register")} className="rounded-md bg-teal-700 px-4 py-2 text-sm font-semibold text-white hover:bg-teal-800">
                                Bắt đầu
                            </button>
                        </>
                    ) : (
                        <div className="relative" ref={accountRef}>
                            <button type="button" onClick={() => setAccountOpen((open) => !open)} aria-haspopup="menu" aria-expanded={accountOpen} className="flex items-center gap-2 rounded-full border border-neutral-200 p-1 pr-3 text-sm font-medium text-neutral-800 hover:bg-neutral-50">
                                <span className="flex h-8 w-8 items-center justify-center rounded-full bg-neutral-950 text-xs font-semibold text-white">{getInitials(session.user.displayName)}</span>
                                <span>Tài khoản</span>
                            </button>
                            {accountOpen && (
                                <div role="menu" className="absolute right-0 mt-2 w-52 overflow-hidden rounded-lg border border-neutral-200 bg-white py-1 shadow-lg">
                                    <Link href="/account" role="menuitem" className="block px-4 py-2 text-sm text-neutral-700 hover:bg-neutral-50">Tổng quan</Link>
                                    <Link href="/account/history" role="menuitem" className="block px-4 py-2 text-sm text-neutral-700 hover:bg-neutral-50">Lịch sử tài khoản</Link>
                                    <button type="button" role="menuitem" onClick={onLogout} className="block w-full px-4 py-2 text-left text-sm text-neutral-700 hover:bg-neutral-50">Đăng xuất</button>
                                </div>
                            )}
                        </div>
                    )}
                </div>

                <button type="button" onClick={() => setMobileOpen((open) => !open)} aria-expanded={mobileOpen} aria-controls="mobile-navigation" aria-label={mobileOpen ? "Đóng menu" : "Mở menu"} className="ml-auto flex h-10 w-10 items-center justify-center rounded-md border border-neutral-200 text-neutral-800 lg:hidden">
                    {mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
                </button>
            </nav>

            {mobileOpen && (
                <div id="mobile-navigation" className="border-t border-neutral-200 bg-white px-4 py-4 lg:hidden">
                    <ul className="mx-auto grid max-w-7xl gap-1">{links}</ul>
                    {session === null && (
                        <div className="mx-auto mt-4 grid max-w-7xl grid-cols-2 gap-2 border-t border-neutral-200 pt-4 sm:hidden">
                            <button type="button" onClick={() => onOpenAuth("login")} className="rounded-md border border-neutral-300 px-3 py-2 text-sm font-medium text-neutral-800">Đăng nhập</button>
                            <button type="button" onClick={() => onOpenAuth("register")} className="rounded-md bg-teal-700 px-3 py-2 text-sm font-semibold text-white">Bắt đầu</button>
                        </div>
                    )}
                </div>
            )}
        </header>
    );
}
