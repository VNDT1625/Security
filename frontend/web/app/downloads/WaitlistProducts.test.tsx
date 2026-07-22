import {fireEvent,render,screen,waitFor} from "@testing-library/react";
import {afterEach,describe,expect,it,vi} from "vitest";
import {WaitlistProducts} from "./WaitlistProducts";

afterEach(()=>vi.restoreAllMocks());

describe("WaitlistProducts",()=>{
 it("submits a product-specific email and confirms registration",async()=>{
  const request=vi.spyOn(globalThis,"fetch").mockImplementation(async input=>new Response(
   JSON.stringify(String(input).endsWith("/releases")?{releases:{}}:{registered:true}),
   {status:200,headers:{"Content-Type":"application/json"}},
  ));
  render(<WaitlistProducts/>);
  fireEvent.change(screen.getByLabelText("Email nhận thông báo",{selector:"#waitlist-windows"}),{target:{value:"user@example.com"}});
  fireEvent.click(screen.getByRole("button",{name:"Thông báo khi phát hành"}));
  await waitFor(()=>expect(screen.getByText(/Đã đăng ký\. Prewise/)).toBeInTheDocument());
  expect(request).toHaveBeenCalledWith("http://localhost:8000/v1/waitlist",expect.objectContaining({body:JSON.stringify({email:"user@example.com",product:"windows"})}));
 });

 it("explains duplicate registrations without presenting an error",async()=>{
  vi.spyOn(globalThis,"fetch").mockImplementation(async input=>new Response(
   JSON.stringify(String(input).endsWith("/releases")?{releases:{}}:{registered:false}),
   {status:200,headers:{"Content-Type":"application/json"}},
  ));
  render(<WaitlistProducts/>);
  fireEvent.change(screen.getByLabelText("Email nhận thông báo",{selector:"#waitlist-browser_extension"}),{target:{value:"known@example.com"}});
  fireEvent.click(screen.getByRole("button",{name:"Tham gia danh sách chờ"}));
  await waitFor(()=>expect(screen.getByText(/đã có trong danh sách/i)).toBeInTheDocument());
 });

 it("keeps the form retryable after a server error",async()=>{
  vi.spyOn(globalThis,"fetch").mockImplementation(async input=>String(input).endsWith("/releases")
   ?new Response(JSON.stringify({releases:{}}),{status:200,headers:{"Content-Type":"application/json"}})
   :new Response(null,{status:503}));
  render(<WaitlistProducts/>);
  fireEvent.change(screen.getByLabelText("Email nhận thông báo",{selector:"#waitlist-windows"}),{target:{value:"user@example.com"}});
  fireEvent.click(screen.getByRole("button",{name:"Thông báo khi phát hành"}));
  await waitFor(()=>expect(screen.getByText(/Không thể đăng ký lúc này/)).toBeInTheDocument());
  expect(screen.getByRole("button",{name:"Thông báo khi phát hành"})).toBeEnabled();
 });
});
