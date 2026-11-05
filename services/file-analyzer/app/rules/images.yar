// Cobertura intencionalmente limitada: indicadores de prueba, no malware universal.
rule STEGO_EICAR_Test_Indicator {
    meta:
        description = "Indicador del archivo de prueba EICAR; no malware real"
        version = "1"
    strings:
        $marker = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii
    condition:
        filesize <= 5242880 and $marker
}

rule STEGO_Reproducible_Test_Marker {
    meta:
        description = "Marcador inerte para pruebas de cuarentena reproducibles"
        version = "1"
    strings:
        $marker = "SECURECHAT_YARA_TEST_MARKER_V1" ascii
    condition:
        filesize <= 5242880 and $marker
}
