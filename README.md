![Flyer](https://raw.githubusercontent.com/Bravxo/Simple-URL-Inspector/main/images/flyer.png)



# Simple URL Inspector

**Simple URL Inspector** es una herramienta en Python diseñada para analizar cualquier URL que creas sospechosa y detectar posibles indicadores de phishing o malware.  
No depende de whitelist o blacklist, simplemente se basa en señales técnicas y de contenido reales para evaluar el riesgo.

---

## 📖 Descripción

La herramienta inspecciona una URL y devuelve un informe con:
- Dominio, subdominio y TLD → para verificar legitimidad.
- Redirecciones → detecta cadenas largas o sospechosas.
- Título de la página → útil para identificar imitaciones.
- Formularios de login y OTP → posibles intentos de robo de credenciales.
- Palabras clave sospechosas → términos como “login”, “verify”, “password”.
- Hash del favicon → para detectar íconos falsificados.
- Scripts JavaScript → identifica ofuscación o comportamientos tipo keylogger.
- Tipo de contenido y descargas automáticas → alerta sobre archivos peligrosos.
- Score de riesgo (0–100) → basado en señales técnicas objetivas.

---

## 🎯 Contexto de uso

Este inspector es útil en
- **Análisis de ciberseguridad** → evaluar enlaces sospechosos recibidos por correo o mensajería.  
- **Educación** → aprender cómo detectar indicadores técnicos de phishing.  
- **Forense digital** → apoyo en investigaciones de URLs maliciosas.  
- **Uso personal** → verificar enlaces antes de abrirlos en tu navegador.

---

## ⚙️ Instalación y uso

### 1. Clonar el repositorio y entrar en èl
git clone https://github.com/Bravxo/Simple-URL-Inspector.git
cd Simple-URL-Inspector

### 2. Instalar las dependencias
pip install -r requirements.txt
o de tener inconvenientes utilizar pip install -r requirements.txt --break-system-packages 

### 3. Ejecutar la herramienta
python3 simpleinspector.py https://www.microsoft.com

########### EJEMPLO DE RESULTADO ###########

=== Simple URL Inspector ===

URL final: https://www.microsoft.com
Dominio: microsoft.com (Subdominio: www, TLD: com)
Redirecciones: 0 → ['https://www.microsoft.com']
Título de la página: Microsoft – Official Home Page
Formulario de login: False
Campo OTP: False
Palabras clave sospechosas: —
Favicon hash: 3f2a....c9d
Scripts detectados: 12 → —
Tipo de contenido: text/html; charset=utf-8
Descarga automática sospechosa: False

>>> Riesgo estimado: 0/100 <<<
