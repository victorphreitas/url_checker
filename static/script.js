function normalizeUrl(url) {
  url = url.trim();
  // Remove any leading/trailing spaces and slashes
  url = url.replace(/^\/+|\/+$/g, '');
  
  // Add http:// if no protocol exists
  if (!/^https?:\/\//i.test(url)) {
    // Check if it starts with www.
    if (/^www\./i.test(url)) {
      url = 'http://' + url;
    } else {
      url = 'http://www.' + url;
    }
  }
  return url;
}

document.getElementById("urlForm").addEventListener("submit", async function (e) {
  e.preventDefault();
  
  // Get elements
  const urlInput = document.getElementById("urlInput");
  const submitBtn = this.querySelector('button[type="submit"]');
  const resultDiv = document.getElementById("result");
  
  // Normalize the URL before processing
  let inputUrl = urlInput.value;
  try {
    inputUrl = normalizeUrl(inputUrl);
  } catch (error) {
    resultDiv.innerHTML = `
      <div class="error-card">
        <span class="error-icon">❌</span>
        <div>
          <h3 class="error-title">URL inválida</h3>
          <p class="error-detail">Formato de URL não reconhecido</p>
        </div>
      </div>
    `;
    return;
  }
  
  // Show loading state
  submitBtn.disabled = true;
  submitBtn.innerHTML = 'Analisando... <span class="spinner"></span>';
  resultDiv.innerHTML = '<div class="loading-message">Verificando URL...</div>';
  
  try {
    const formData = new FormData();
    formData.append("url", inputUrl);

    const res = await fetch("/check_url", { 
      method: "POST", 
      body: formData 
    });
    
    if (!res.ok) throw new Error(`Erro HTTP: ${res.status}`);
    
    const data = await res.json();

    // Clear previous results
    resultDiv.innerHTML = '';
    
    if (!data.valid) {
      resultDiv.innerHTML = `
        <div class="error-card">
          <span class="error-icon">❌</span>
          <div>
            <h3 class="error-title">URL inválida</h3>
            <p class="error-detail">Por favor, verifique se a URL está correta e inclui http:// ou https://</p>
          </div>
        </div>
      `;
      return;
    }

    let messages = [];
    const warningCount = [data.suspicious_patterns, data.recent_domain, data.private_owner].filter(Boolean).length;

    if (data.suspicious_patterns) messages.push({
      text: "Padrões suspeitos detectados na URL",
      type: "warning"
    });
    if (data.recent_domain) messages.push({
      text: "Domínio registrado há menos de 6 meses",
      type: "warning"
    });
    if (data.private_owner) messages.push({
      text: "Informações do proprietário ocultas",
      type: "warning"
    });
    if (data.redirect_chain?.length > 1) messages.push({
      text: `${data.redirect_chain.length} redirecionamentos detectados`,
      type: "info"
    });

    if (messages.length === 0) {
      messages.push({
        text: "Nenhum sinal suspeito detectado",
        type: "success"
      });
    }

    // Build results HTML
    resultDiv.innerHTML = `
      <div class="result-summary ${warningCount > 0 ? 'has-warnings' : 'is-safe'}">
        <h3 class="summary-title">
          ${warningCount > 0 ? '⚠️ Possíveis problemas encontrados' : '✅ URL parece segura'}
        </h3>
        <p class="summary-detail">
          ${warningCount > 0 ? 
            `${warningCount} ${warningCount === 1 ? 'problema' : 'problemas'} encontrados` : 
            'Nenhum problema detectado na análise'}
        </p>
      </div>
      
      <ul class="result-details">
        ${messages.map(msg => `
          <li class="detail-item ${msg.type}">
            <span class="detail-icon">
              ${msg.type === 'success' ? '✅' : 
               msg.type === 'warning' ? '⚠️' : '🔀'}
            </span>
            <span class="detail-text">${msg.text}</span>
          </li>
        `).join('')}
      </ul>
      
      ${data.redirect_chain?.length > 1 ? `
        <div class="redirect-section">
          <h4 class="redirect-title">Cadeia de redirecionamento:</h4>
          <ol class="redirect-chain">
            ${data.redirect_chain.map(url => `
              <li class="redirect-url">${url}</li>
            `).join('')}
          </ol>
        </div>
      ` : ''}
    `;
    
  } catch (error) {
    console.error("Error:", error);
    resultDiv.innerHTML = `
      <div class="error-card">
        <span class="error-icon">⚠️</span>
        <div>
          <h3 class="error-title">Erro na análise</h3>
          <p class="error-detail">Não foi possível completar a verificação. Tente novamente.</p>
        </div>
      </div>
    `;
  } finally {
    // Reset button
    submitBtn.disabled = false;
    submitBtn.textContent = 'Verificar URL';
  }
});