// Client-side password length pre-check for UX only.
// The authoritative check (length + common-password lookup) runs
// server-side in app.py - never trust this check alone.
function checkPassword() {
  const pw = document.getElementById("password").value;
  if (pw.length < 8 || pw.length > 64) {
    alert("Password must be between 8 and 64 characters.");
    return false;
  }
  return true;
}
