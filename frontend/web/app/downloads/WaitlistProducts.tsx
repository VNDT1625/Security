"use client";

import {FormEvent, useEffect, useState} from "react";
import {MonitorDown, Puzzle} from "lucide-react";
import styles from "./downloads.module.css";

type ProductKey="windows"|"browser_extension";
type FormState={email:string;status:"idle"|"submitting"|"success"|"error";message:string};
type Release={version:string;downloadUrl:string;checksumSha256:string;signatureNote?:string|null};

const products=[
 {key:"windows" as const,icon:MonitorDown,name:"Prewise cho Windows",detail:"Ứng dụng bảo vệ trên máy tính, kiểm tra liên kết và tệp trước khi mở.",action:"Thông báo khi phát hành"},
 {key:"browser_extension" as const,icon:Puzzle,name:"Tiện ích trình duyệt",detail:"Cảnh báo website đáng ngờ trực tiếp trên Chrome, Edge và các trình duyệt Chromium.",action:"Tham gia danh sách chờ"},
];

const initialState:FormState={email:"",status:"idle",message:""};

function apiBase():string{return (process.env.NEXT_PUBLIC_API_BASE_URL??"http://localhost:8000").replace(/\/+$/,"");}

export function WaitlistProducts(){
 const [forms,setForms]=useState<Record<ProductKey,FormState>>({windows:{...initialState},browser_extension:{...initialState}});
 const [releases,setReleases]=useState<Partial<Record<ProductKey,Release>>>({});
 useEffect(()=>{void fetch(`${apiBase()}/v1/waitlist/releases`,{cache:"no-store"}).then(response=>response.ok?response.json():Promise.reject()).then((data:{releases?:Partial<Record<ProductKey,Release>>})=>setReleases(data.releases??{})).catch(()=>undefined);},[]);
 const update=(product:ProductKey,change:Partial<FormState>)=>setForms(current=>({...current,[product]:{...current[product],...change}}));

 async function submit(event:FormEvent<HTMLFormElement>,product:ProductKey){
  event.preventDefault();
  const email=forms[product].email.trim();
  update(product,{status:"submitting",message:""});
  try{
   const response=await fetch(`${apiBase()}/v1/waitlist`,{
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({email,product}),
   });
   if(!response.ok)throw new Error(response.status===422?"Vui lòng nhập một địa chỉ email hợp lệ.":"Không thể đăng ký lúc này. Vui lòng thử lại.");
   const result=await response.json() as {registered:boolean};
   update(product,{status:"success",message:result.registered?"Đã đăng ký. Prewise sẽ thông báo cho bạn khi sản phẩm sẵn sàng.":"Email này đã có trong danh sách. Bạn không cần đăng ký lại."});
  }catch(error){
   update(product,{status:"error",message:error instanceof Error?error.message:"Không thể đăng ký lúc này. Vui lòng thử lại."});
  }
 }

 return <section className="download-grid" aria-label="Sản phẩm sắp phát hành">
  {products.map(product=>{
   const Icon=product.icon,state=forms[product.key],done=state.status==="success",release=releases[product.key];
   return <article key={product.key}>
    <div className="download-icon"><Icon aria-hidden/></div>
    <span>{release?`PHIÊN BẢN ${release.version}`:"SẮP RA MẮT"}</span>
    <h2>{product.name}</h2>
    <p>{product.detail}</p>
    {release?<div className={styles.release}>
     <a href={release.downloadUrl} rel="noopener noreferrer">Tải xuống an toàn</a>
     <p>SHA-256: <code>{release.checksumSha256}</code></p>
     {release.signatureNote&&<small>{release.signatureNote}</small>}
    </div>:<form className={styles.form} onSubmit={event=>void submit(event,product.key)}>
     <label htmlFor={`waitlist-${product.key}`}>Email nhận thông báo</label>
     <div className={styles.controls}>
      <input id={`waitlist-${product.key}`} type="email" autoComplete="email" required maxLength={320} placeholder="ban@example.com" value={state.email} onChange={event=>update(product.key,{email:event.target.value,status:"idle",message:""})}/>
      <button type="submit" disabled={state.status==="submitting"||done}>{state.status==="submitting"?"Đang đăng ký…":done?"Đã đăng ký":product.action}</button>
     </div>
     <p className={state.status==="error"?styles.error:styles.message} aria-live="polite">{state.message}</p>
    </form>}
   </article>;
  })}
 </section>;
}
