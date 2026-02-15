# pg_dictionary_generate 🛡️

**Advanced Pentesting Dictionary Generator for PostgreSQL**

Motor de generación de diccionarios (wordlists) de alto rendimiento desarrollado en PL/pgSQL. Diseñado para auditores de seguridad y pentester que necesitan generar permutaciones de contraseñas basadas en patrones de comportamiento humano directamente en la base de datos.

## 🚀 Características Principales

* **Lógica Multietapa**: Transforma semillas simples mediante variaciones de caja (Case), Leetspeak, sufijos temporales y símbolos especiales.
* **Control de Profundidad**: Permite definir la agresividad del ataque (Sufijos vs Prefijos vs Infijos).
* **Evasión de IDS/WAF**: Opción de mezcla aleatoria (`p_shuffle`) para romper patrones secuenciales.
* **Alto Rendimiento**: Capacidad de persistencia en tablas `UNLOGGED` (sin rastro en WAL) para escrituras masivas ultra rápidas.
* **Balanceo Inteligente**: Reparto equitativo de la cuota de palabras entre todas las keywords proporcionadas.

---

## 🛠️ Parámetros de la Función

| Parámetro | Tipo | Descripción |
| --- | --- | --- |
| `p_keywords` | `text[]` | Array de palabras semilla (Ej: `ARRAY['admin', 'soporte']`). |
| `p_persistir` | `boolean` | `true` para volcar resultados en `security.diccionario_generado`. |
| `p_anio_inicio/fin` | `int` | Rango de años para permutaciones temporales. |
| `p_profundidad` | `int` | Nivel de agresividad (1: Básico, 2: Medio, 3: Agresivo). |
| `p_max_palabras` | `int` | Límite total de palabras a generar (Balanceado por keyword). |
| `p_shuffle` | `boolean` | `true` para desordenar aleatoriamente la salida. |

---

## 📖 Ejemplos de Uso

### 1. Generación Básica con Persistencia

Este ejemplo genera un diccionario de 10,000 palabras balanceadas y las guarda en la tabla de seguridad.

```sql
SELECT count(*) FROM security.pg_dictionary_generate(
    p_keywords     => ARRAY['Corporativo', 'Seguridad'], 
    p_persistir    => true,                         
    p_anio_inicio  => 2020,                         
    p_anio_fin     => 2026,                         
    p_profundidad  => 3,                            
    p_max_palabras => 10000,                        
    p_shuffle      => true                          
);

```

### 2. Expansión Masiva (Bloque Anónimo)

Utiliza este bloque para ejecutar múltiples pasadas y construir un diccionario de gran escala con feedback en tiempo real en la consola.

```sql
DO $$
DECLARE
    -- Configuración
    v_iteraciones   integer := 100; -- Cantidad de ejecuciones (N)
    v_i             integer;
    v_conteo_actual bigint;
    -- Secuencias ANSI para actualización de línea en consola psql
    v_clear_line    text := E'\r\x1b[K'; 
BEGIN
    RAISE NOTICE 'Iniciando expansión de diccionario Pentesting...';

    FOR v_i IN 1..v_iteraciones LOOP
        
        -- Ejecución de la función (Generación masiva balanceada)
        PERFORM security.pg_dictionary_generate(
            p_keywords     => ARRAY['empresa', 'seguridad', 'informacion', 'info', 'desempeño', 'gestion',
                'mesadeayuda', 'mesa', 'gestion de desempeño', 'hoja de vida', 
                'circulares', 'decisiones', 'Inicio', 'Directorio', 'Quiénes Somos',
                'Circular', 'KPI', 'Organigrama', 'Infraestructura Tecnológica',
                'MC', 'Manual Técnico', 'sucursal', 'oficina', 'universidad',
                'Políticas', 'Estándares', 'Procesos', 'Integridad', 'Disponibilidad',
                'Gobierno de Seguridad', 'Marco de Gobierno', 'Seguridad de la Información'],
            p_persistir    => true, 
            p_anio_inicio  => 2020,
            p_anio_fin     => 2026,
            p_profundidad  => 3,
            p_max_palabras => 10000,
            p_shuffle      => true
        );

        -- Conteo de registros acumulados en tabla UNLOGGED
        SELECT count(*) INTO v_conteo_actual FROM security.diccionario_generado;

        -- Actualización dinámica de progreso en consola
        RAISE NOTICE '%[PROGRESO] Ejecución: %/% | Total Palabras Únicas: %', 
                     v_clear_line, v_i, v_iteraciones, v_conteo_actual;

    END LOOP;

    RAISE NOTICE E'\n---------------------------------------------------------';
    RAISE NOTICE 'DICCIONARIO LISTO: % registros generados.', v_conteo_actual;
END $$;

```

---

## 🔍 Verificación de Datos

Para consultar el diccionario generado y validar la calidad de las permutaciones:

```sql
-- Consultar los primeros 15 registros ordenados alfabéticamente
SELECT * FROM security.diccionario_generado ORDER BY word ASC LIMIT 15;

-- Limpiar diccionario para una nueva auditoría
-- TRUNCATE TABLE security.diccionario_generado RESTART IDENTITY;

```

---

## ⚖️ Niveles de Profundidad (`p_profundidad`)

| Nivel | Tipo | Descripción | Ejemplo |
| --- | --- | --- | --- |
| **1** | **Básico** | Solo símbolos al FINAL (Patrón común). | `Admin@2025` |
| **2** | **Medio** | Habilita PREFIJOS (Símbolos al inicio). | `@Admin2025` |
| **3** | **Agresivo** | Combinaciones complejas y dobles símbolos. | `!Admin#2025` |

---

## ⚠️ Seguridad y Privilegios

* La función utiliza `SECURITY INVOKER`.
* Se recomienda restringir el permiso de ejecución solo a roles de auditoría técnica.
* El uso de tablas `UNLOGGED` garantiza que el diccionario no persista en copias de seguridad de logs (WAL), protegiendo la volatilidad del proceso de pentesting.

---

**Autor:** CR0NYM3X
**Versión:** 1.2.0
