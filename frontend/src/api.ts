export type User = { id:string; username:string; display_name:string; role:string };
export type Row = Record<string, any>;
const API_BASE = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");
function cookie(name:string){return document.cookie.split("; ").find((p)=>p.startsWith(name+"="))?.split("=").slice(1).join("=")??"";}
function getCsrf(): string {
  return decodeURIComponent(cookie("clinic_csrf")) || sessionStorage.getItem("clinic_csrf") || "";
}
export async function api<T=any>(path:string,options:RequestInit={}):Promise<T>{
  const method=(options.method??"GET").toUpperCase(); const headers=new Headers(options.headers??{});
  if(options.body&&!headers.has("Content-Type"))headers.set("Content-Type","application/json");
  if(!["GET","HEAD","OPTIONS"].includes(method)&&path!=="/api/auth/login"&&path!=="/api/auth/register"){
    const token = getCsrf();
    if(token) headers.set("X-CSRF-Token", token);
  }
  const target = path.startsWith("http://") || path.startsWith("https://") ? path : `${API_BASE}${path}`;
  const response=await fetch(target,{...options,method,headers,credentials:"include"});
  const csrfHeader = response.headers.get("X-CSRF-Token");
  if(csrfHeader) {
    try { sessionStorage.setItem("clinic_csrf", csrfHeader); } catch {}
  }
  const payload=await response.json().catch(()=>({}));
  if(!response.ok)throw new Error(typeof payload.detail === "string" ? payload.detail : "Request failed (" + response.status + ")");
  return payload as T;
}
export const json=(body:unknown)=>JSON.stringify(body);
export function localDateTime(value?:string){return value?new Date(value).toLocaleString([],{dateStyle:"medium",timeStyle:"short"}):"—";}
