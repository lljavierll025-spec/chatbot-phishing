// static/app.js
document.addEventListener("DOMContentLoaded", () => {
  const chat = document.getElementById("chat");
  const chatContainer = document.querySelector(".main");
  const input = document.getElementById("inputField");
  const sendBtn = document.getElementById("sendBtn");
  const analyzeBtn = document.getElementById("analyzeBtn");
  const fileInput = document.getElementById("fileInput");

  // Mostrar mensaje de bienvenida (igual que en desktop)
  const welcome = `👋 <b>Bienvenido al ChatBot Detector de Phishing</b><br><br>
  Puedo ayudarte a:<br>
  📖 Aprender sobre técnicas de phishing<br>
  🔎 Entender conceptos como SPF, DKIM y DMARC<br>
  🔍 Analizar correos electrónicos sospechosos<br><br>
  Escribe una pregunta o usa el botón <b>'Analizar .eml'</b> para verificar un correo.<br>
  <i>Tip: Escribe 'salir' o 'adios' cuando quieras despedirte.</i>`;
  addMessage(welcome, true);

  sendBtn.addEventListener("click", sendMessage);
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") sendMessage();
  });

  analyzeBtn.addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", handleFile);

  // Delegación de eventos para botones dentro del chat
  chat.addEventListener("click", (e) => {
    if (e.target.classList.contains("chat-upload-btn")) {
      fileInput.click();
    }
  });

  function addMessage(htmlContent, isBot) {
    const row = document.createElement("div");
    row.className = "message-row " + (isBot ? "bot-wrap" : "user-wrap");

    const bubble = document.createElement("div");
    bubble.className = "msg-bubble " + (isBot ? "bot-bubble" : "user-bubble");

    const sender = document.createElement("div");
    sender.className = "sender-label";
    sender.innerText = isBot ? "🤖 Bot" : "👤 Tú";

    const content = document.createElement("div");
    content.innerHTML = htmlContent;

    bubble.appendChild(sender);
    bubble.appendChild(content);
    row.appendChild(bubble);
    chat.appendChild(row);
    // Scroll the chat container so the newest message stays in view
    requestAnimationFrame(scrollChatToBottom);
  }

  function scrollChatToBottom() {
    const target = chatContainer;
    if (target && typeof target.scrollTo === "function") {
      target.scrollTo({ top: target.scrollHeight, behavior: "smooth" });
      return;
    }

    if (target) {
      target.scrollTop = target.scrollHeight;
      return;
    }

    window.scrollTo({ top: document.body.scrollHeight, behavior: "smooth" });
  }

  async function sendMessage() {
    const text = input.value.trim();
    if (!text) return;
    input.value = "";
    addMessage(escapeHtml(text), false);

    // Llamada al backend
    try {
      const resp = await fetch("/api/message", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
      });
      const data = await resp.json();
      if (!data.ok) {
        addMessage("❌ Error en la comunicación con el servidor.", true);
        return;
      }
      addMessage(data.reply, true);

      if (data.is_goodbye) {
        // comportamiento de despedida: deshabilitar UI
        input.disabled = true;
        sendBtn.disabled = true;
        analyzeBtn.disabled = true;
        setTimeout(() => {
          addMessage("👋 ¡Hasta luego!", true);
        }, 500);
      }
      // Si la intención fue ANALISIS_PETICION el backend normalmente lo marca en 'intent'
      // El servidor original abría dialogo - en web pedimos al usuario subir archivo con botón
    } catch (err) {
      console.error(err);
      addMessage("❌ No se pudo contactar al servidor.", true);
    }
  }

  async function handleFile(ev) {
    const file = ev.target.files[0];
    if (!file) return;
    // Mostrar mensaje usuario con nombre archivo
    addMessage(`<b>Archivo seleccionado:</b> ${escapeHtml(file.name)}`, false);

    const fd = new FormData();
    fd.append("file", file);
    analyzeBtn.disabled = true;
    analyzeBtn.innerText = "⏳ Analizando...";

    try {
      const resp = await fetch("/api/analyze", { method: "POST", body: fd });
      const data = await resp.json();
      if (!data.ok) {
        addMessage(
          `❌ Error: ${escapeHtml(data.error || "Error desconocido")}`,
          true
        );
      } else {
        // data.html viene listo para insertar
        addMessage(data.html, true);
      }
    } catch (err) {
      console.error(err);
      addMessage("❌ Error en el análisis.", true);
    } finally {
      analyzeBtn.disabled = false;
      analyzeBtn.innerText = "📁 Analizar .eml";
      fileInput.value = "";
    }
  }

  function escapeHtml(unsafe) {
    return unsafe
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }
});
