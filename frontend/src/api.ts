export type User = { id:string; username:string; display_name:string; role:string };
export type Row = Record<string, any>;
function cookie(name:string){return document.cookie.split("; ").find((p)=>p.startsWith(name+"="))?.split("=").slice(1).join("=")??"";}
export async function api<T=any>(path:string,options:RequestInit={}):Promise<T>{
  const method=(options.method??"GET").toUpperCase(); const headers=new Headers(options.headers??{});
  if(options.body&&!headers.has("Content-Type"))headers.set("Content-Type","application/json");
  if(!["GET","HEAD","OPTIONS"].includes(method)&&path!=="/api/auth/login"&&path!=="/api/auth/register")headers.set("X-CSRF-Token",decodeURIComponent(cookie("clinic_csrf")));
  const response=await fetch(path,{...options,method,headers,credentials:"include"});
  const payload=await response.json().catch(()=>({}));
  if(!response.ok)throw new Error(typeof payload.detail === "string" ? payload.detail : "Request failed (" + response.status + ")");
  return payload as T;
}
export const json=(body:unknown)=>JSON.stringify(body);
export function localDateTime(value?:string){return value?new Date(value).toLocaleString([],{dateStyle:"medium",timeStyle:"short"}):"—";}
