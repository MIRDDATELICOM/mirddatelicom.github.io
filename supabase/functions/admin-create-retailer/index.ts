import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const json = (status: number, body: Record<string, unknown>) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json(405, { error: "Method not allowed" });

  try {
    const url = Deno.env.get("SUPABASE_URL");
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!url || !anonKey || !serviceKey) {
      return json(500, { error: "Server configuration is incomplete." });
    }

    const authHeader = req.headers.get("Authorization");
    if (!authHeader?.startsWith("Bearer ")) return json(401, { error: "Please sign in as Admin." });

    const caller = createClient(url, anonKey, {
      global: { headers: { Authorization: authHeader } },
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: userData, error: userError } = await caller.auth.getUser();
    if (userError || !userData.user) return json(401, { error: "Invalid session." });

    const { data: profile, error: profileError } = await caller
      .from("profiles").select("role").eq("id", userData.user.id).single();
    if (profileError || profile?.role !== "admin") {
      return json(403, { error: "Admin permission required." });
    }

    const body = await req.json();
    const fullName = String(body.full_name ?? "").trim();
    const rawPhone = String(body.phone ?? "");
    const phone = rawPhone.replace(/\D/g, "");
    const password = String(body.password ?? "");

    if (fullName.length < 2 || fullName.length > 80) {
      return json(400, { error: "নাম ২ থেকে ৮০ অক্ষরের মধ্যে লিখুন।" });
    }
    if (!/^\d{10}$/.test(phone)) {
      return json(400, { error: "সঠিক ১০ অঙ্কের ভারতীয় মোবাইল নম্বর দিন।" });
    }
    if (password.length < 8 || password.length > 72) {
      return json(400, { error: "Password ৮ থেকে ৭২ অক্ষরের মধ্যে হতে হবে।" });
    }

    const email = "91" + phone + "@example.com";
    const admin = createClient(url, serviceKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: created, error: createError } = await admin.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: { full_name: fullName, phone: rawPhone },
    });

    if (createError || !created.user) {
      const message = /already|registered|exists/i.test(createError?.message ?? "")
        ? "এই মোবাইল নম্বর দিয়ে Retailer আগে থেকেই তৈরি আছে।"
        : "Retailer তৈরি করা যায়নি: " + (createError?.message ?? "Unknown error");
      return json(400, { error: message });
    }

    // The auth.users trigger creates the matching profile and retailer_id.
    const { data: savedProfile, error: saveError } = await admin
      .from("profiles")
      .update({ full_name: fullName, phone })
      .eq("id", created.user.id)
      .select("retailer_id")
      .single();

    if (saveError) {
      await admin.auth.admin.deleteUser(created.user.id);
      return json(500, { error: "Retailer profile save করা যায়নি: " + saveError.message });
    }

    return json(200, {
      success: true,
      retailer_id: savedProfile.retailer_id,
      phone,
      message: "Retailer account তৈরি হয়েছে।",
    });
  } catch (_error) {
    return json(400, { error: "Request সঠিক নয়। তথ্য পরীক্ষা করে আবার চেষ্টা করুন।" });
  }
});
