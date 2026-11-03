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

    const { data: callerProfile, error: callerProfileError } = await caller
      .from("profiles").select("role").eq("id", userData.user.id).single();
    if (callerProfileError || callerProfile?.role !== "admin") {
      return json(403, { error: "Admin permission required." });
    }

    const body = await req.json();
    const retailerId = String(body.retailer_id ?? "").trim();
    const fullName = String(body.full_name ?? "").trim();
    const phone = String(body.phone ?? "").replace(/\D/g, "");

    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(retailerId)) {
      return json(400, { error: "Retailer ID সঠিক নয়।" });
    }
    if (fullName.length < 2 || fullName.length > 80) {
      return json(400, { error: "নাম ২ থেকে ৮০ অক্ষরের মধ্যে লিখুন।" });
    }
    if (!/^\d{10}$/.test(phone)) {
      return json(400, { error: "সঠিক ১০ অঙ্কের ভারতীয় মোবাইল নম্বর দিন।" });
    }

    const admin = createClient(url, serviceKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });

    const { data: targetProfile, error: targetError } = await admin
      .from("profiles").select("id,role").eq("id", retailerId).single();
    if (targetError || !targetProfile || targetProfile.role !== "retailer") {
      return json(404, { error: "Retailer account পাওয়া যায়নি।" });
    }

    const newEmail = "91" + phone + "@example.com";
    const { data: authData, error: authFetchError } = await admin.auth.admin.getUserById(retailerId);
    if (authFetchError || !authData.user) {
      return json(404, { error: "Retailer login account পাওয়া যায়নি।" });
    }
    const oldEmail = authData.user.email ?? undefined;

    const { error: authUpdateError } = await admin.auth.admin.updateUserById(retailerId, {
      email: newEmail,
      email_confirm: true,
      user_metadata: { ...authData.user.user_metadata, full_name: fullName, phone },
    });
    if (authUpdateError) {
      const duplicate = /already|registered|exists/i.test(authUpdateError.message);
      return json(400, { error: duplicate
        ? "এই মোবাইল নম্বর দিয়ে অন্য একটি account আগে থেকেই আছে।"
        : "Login ID পরিবর্তন করা যায়নি: " + authUpdateError.message });
    }

    const { error: profileUpdateError } = await admin
      .from("profiles").update({ full_name: fullName, phone }).eq("id", retailerId);

    if (profileUpdateError) {
      if (oldEmail) {
        await admin.auth.admin.updateUserById(retailerId, { email: oldEmail, email_confirm: true });
      }
      return json(500, { error: "Profile update ব্যর্থ হয়েছে; Login ID আগের অবস্থায় ফেরানোর চেষ্টা করা হয়েছে। Admin panel থেকে তথ্য যাচাই করুন।" });
    }

    return json(200, {
      success: true,
      phone,
      message: "Retailer নাম, Profile ও Login মোবাইল নম্বর আপডেট হয়েছে।",
    });
  } catch (_error) {
    return json(400, { error: "Request সঠিক নয়। তথ্য পরীক্ষা করে আবার চেষ্টা করুন।" });
  }
});
