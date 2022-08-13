document.getElementById("login").addEventListener("click", async () => {
  const username = document.getElementById("username_l").innerHTML;
  const password = document.getElementById("password_l").innerHTML;
  try {
    await fetch(
      "http://127.0.0.1:5000/auth/login",
      JSON.stringify({ username, password })
    );
    const parts = window.location.href.split("/");
    const base = parts.slice(0, parts.length - 1).join("/");
    window.location.href = base + "/index.html";
  } catch (err) {
    console.log(err);
  }
});

document.getElementById("signup").addEventListener("click", async () => {
  const username = document.getElementById("username_r").innerHTML;
  const password = document.getElementById("password_r").innerHTML;
  try {
    await fetch(
      "http://127.0.0.1:5000/auth/register",
      JSON.stringify({ username, password })
    );
    const parts = window.location.href.split("/");
    const base = parts.slice(0, parts.length - 1).join("/");
    window.location.href = base + "/index.html";
  } catch (err) {
    console.log(err);
  }
});
