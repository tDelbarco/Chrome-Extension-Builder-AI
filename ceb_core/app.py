import streamlit as st
import json
from core import DOMAnalyzer, parse_html


# Configuración de la página
st.set_page_config(page_title="DOM Dynamic Analyzer", layout="wide")

st.title("🔍 Analizador de Contenedores Dinámicos")
st.markdown("Sube dos versiones de un mismo HTML para identificar cambios en la estructura del DOM.")

# --- BARRA LATERAL: Carga de Archivos ---
with st.sidebar:
    st.header("Configuración")
    file1 = st.file_uploader("Archivo HTML 1 (Base)", type=["html"])
    file2 = st.file_uploader("Archivo HTML 2 (Comparación)", type=["html"])
    
    st.info("La lógica analizará las diferencias estructurales entre ambos archivos.")

# --- AREA PRINCIPAL ---
if file1 and file2:
    try:
        # Parsear los contenidos
        content1 = file1.read().decode("utf-8", errors="ignore")
        content2 = file2.read().decode("utf-8", errors="ignore")
        
        soup1 = parse_html(content1)
        soup2 = parse_html(content2)

        # Inicializar el objeto de core.py
        analyzer = DOMAnalyzer(soup1, soup2)

        # Botón para ejecutar el análisis
        if st.button("Ejecutar Análisis", type="primary"):
            with st.spinner("Analizando estructuras..."):
                # Llamar al método solicitado
                results = analyzer.classify_dynamic_containers()
            
            if results:
                # 1. Ejecutar la detección de variables usando el método de la clase
                with st.spinner("Detectando campos con valores variables..."):
                    variables = analyzer.detect_variables(results)
                
                # 2. Crear el objeto final consolidado
                final_output = {
                    "structures": results,
                    "variables": variables
                }
                
                # 3. Mostrar el JSON completo en un cuadro copiable
                st.subheader("Resultado Final (Estructura + Variables)")
                json_response = json.dumps(final_output, indent=4, ensure_ascii=False)
                st.code(json_response, language="json")
                
                # 4. Mostrar una vista previa de las variables encontradas
                if variables:
                    st.subheader("Resumen de Variables")
                    st.write("Se han identificado los siguientes campos que cambian de valor:")
                    
                    # Transformamos a DataFrame para una tabla limpia en Streamlit
                    import pandas as pd
                    df_vars = pd.DataFrame(variables)
                    
                    # Reorganizamos columnas para que sea más legible
                    cols = ["scope", "container", "path", "type", "variation"]
                    st.table(df_vars[[c for c in cols if c in df_vars.columns]])
                else:
                    st.info("No se detectaron variaciones de datos dentro de las estructuras encontradas.")
                    
                # 5. Botón de descarga
                st.download_button(
                    label="Descargar JSON Completo",
                    data=json_response,
                    file_name="dom_analysis_full.json",
                    mime="application/json"
                )
    except Exception as e:
        st.error(f"Ocurrió un error al procesar los archivos: {e}")
else:
    st.info("Por favor, sube ambos archivos HTML en la barra lateral para comenzar.")
