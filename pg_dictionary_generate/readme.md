
# Advanced Wordlist Generator for PostgreSQL (Smart Dictionary)

Este repositorio contiene una potente herramienta en **PL/pgSQL** diseñada para especialistas en ciberseguridad y administradores de bases de datos. La función genera diccionarios de contraseñas dinámicos aplicando mutaciones inteligentes sobre palabras clave (keywords) de entrada.

## 🚀 Características Principales

* **Orden de Ataque Eficiente:** Los resultados se clasifican por peso. Primero se entregan las variantes más probables (palabra exacta, mayúsculas, secuencias comunes) para reducir el tiempo de búsqueda.
* **Motor de Mutación Avanzado:**
* **LeetSpeak:** Sustitución de caracteres por números (`a -> 4`, `e -> 3`, etc.).
* **Case Shuffling:** Mezcla aleatoria de mayúsculas y minúsculas (ej. `tArgEt`).
* **Deformación:** Inversión de texto (`reverse`) y duplicación de caracteres (`TTAARRGGEETT`).


* **Permutación Estructural:** Combina de forma aleatoria la palabra base con símbolos, años y términos comunes (`admin`, `root`, `pass`).
* **Almacenamiento Unlogged:** Soporte para tablas `UNLOGGED`, lo que permite una generación masiva de datos sin sobrecargar el log de transacciones (WAL) de la base de datos.

---

## 🛠️ Instalación

1. Crea el esquema de seguridad si no existe:
```sql
CREATE SCHEMA IF NOT EXISTS security;

```


2. Ejecuta el script SQL para compilar la función `fn_generar_diccionario_avanzado`.

---

## 🧪 Casos de Prueba (Demo)

Utilizando la palabra clave de ejemplo: **`secreto`**

### Test 1: Variantes de Alta Probabilidad

Muestra cómo la función entrega primero los resultados más obvios.

**Query:**

```sql
SELECT password_generated 
FROM security.fn_generar_diccionario_avanzado(
    p_keywords := ARRAY['secreto'],
    p_persistir := true,
    p_max_palabras := 5
);

select * from security.diccionario_generado;

```

**Resultados:**

1. `secreto` (Palabra exacta)
2. `SECRETO` (Mayúsculas)
3. `secreto123` (Patrón más usado)
4. `oterces` (Invertida)
5. `s3cr3t0` (LeetSpeak)

### Test 2: Estructuras Inteligentes

Ejemplo de cómo la función construye contraseñas que cumplen con políticas de complejidad.

**Query:**

```sql
SELECT password_generated 
FROM security.fn_generar_diccionario_avanzado(
    p_keywords := ARRAY['secreto'],
    p_persistir := false,
    p_max_palabras := 500
) 
OFFSET 50 LIMIT 5;

```

**Muestra de resultados:**

* `S3cr3t0.2025!`
* `secreto.admin.2024`
* `SSEECRREETTOO_1`
* `2005!secreto123`
* `sEcReTo@7`

---

## 📊 Arquitectura de Generación

La función opera en tres capas:

1. **Capa de Mutación:** Transforma la palabra base (Leet, Case, Reverse).
2. **Capa de Combinación:** Mezcla las mutaciones con prefijos y sufijos (años, números, símbolos).
3. **Capa de Filtrado:** Elimina duplicados, filtra por longitud y ordena por prioridad de éxito.

---

## ⚠️ Nota de Uso Legal

Esta herramienta ha sido creada exclusivamente con fines educativos y para su uso en auditorías de seguridad debidamente autorizadas. El autor no se hace responsable del mal uso de este software.
