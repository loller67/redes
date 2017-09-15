# coding=utf-8
#!/usr/bin/python3
import random
import sys
import time
import scapy.all as sp
import numpy as np
import requests as req

from scipy import stats
from os import getuid, stat


def detectarOutliers(mediciones):
    rtt_difs = []
    rtt_anterior = 0

    for medicion in mediciones:
        rtt_difs.append(float(medicion[2]) - rtt_anterior)

    outliers_standard = cimbalaStandard(rtt_difs)
    outliers_removiendo = cimbalaRemoviendo(rtt_difs)

    return outliers_standard#, outliers_removiendo


def cimbalaStandard(rtt_difs):
    outliers = []
    if len(rtt_difs) > 0:
        media = np.mean(rtt_difs)
        desvio_standard = np.std(rtt_difs)
        tg = thompson_gamma(rtt_difs)
        #falta completar los cálculos

        for rtt_dif in rtt_difs:
            delta = np.absolute(rtt_dif - media)
            if (delta > tg * desvio_standard):
                outliers.append(rtt_dif)
                print("outlier: " + str(int(rtt_dif * 1000)))

    return outliers


def cimbalaRemoviendo(rtt_difs):
    outliers = []
    if len(rtt_difs) > 0:
        seguir_buscando = True
        while seguir_buscando:
            seguir_buscando = False
            media = np.mean(rtt_difs)
            desvio_standard = np.std(rtt_difs)
            tg = thompson_gamma(rtt_difs)
            outlier = None
            for rtt_dif in rtt_difs:
                delta = np.absolute(rtt_dif - media)
                if (delta > tg * desvio_standard):
                    outlier = rtt_dif
                    print(("outlier removiendo: " + str(int(rtt_dif * 1000))))
                    break
                if outlier:
                    rtt_difs.remove(outlier)
                    outliers.append(outlier)
                    seguir_buscando = True
    return outliers


def thompson_gamma(rtts):
    n = len(rtts)

    t_a_2 = stats.t.ppf(1 - 0.025, n - 2)
    n_root = np.sqrt(n)

    numerator = t_a_2 * (n - 1)
    denominator = n_root * np.sqrt(n - 2 + np.power(t_a_2, 2))

    return numerator / denominator


def iso3166_Pais_A_Continente(codigoPais):
    #"iso 3166 country","continent code"
        dict_PaisAContinente = {
        "A1": "--",
        "A2": "--",
        "AD": "EU",
        "AE": "AS",
        "AF": "AS",
        "AG": "NA",
        "AI": "NA",
        "AL": "EU",
        "AM": "AS",
        "AN": "NA",
        "AO": "AF",
        "AP": "AS",
        "AQ": "AN",
        "AR": "SA",
        "AS": "OC",
        "AT": "EU",
        "AU": "OC",
        "AW": "NA",
        "AX": "EU",
        "AZ": "AS",
        "BA": "EU",
        "BB": "NA",
        "BD": "AS",
        "BE": "EU",
        "BF": "AF",
        "BG": "EU",
        "BH": "AS",
        "BI": "AF",
        "BJ": "AF",
        "BL": "NA",
        "BM": "NA",
        "BN": "AS",
        "BO": "SA",
        "BR": "SA",
        "BS": "NA",
        "BT": "AS",
        "BV": "AN",
        "BW": "AF",
        "BY": "EU",
        "BZ": "NA",
        "CA": "NA",
        "CC": "AS",
        "CD": "AF",
        "CF": "AF",
        "CG": "AF",
        "CH": "EU",
        "CI": "AF",
        "CK": "OC",
        "CL": "SA",
        "CM": "AF",
        "CN": "AS",
        "CO": "SA",
        "CR": "NA",
        "CU": "NA",
        "CV": "AF",
        "CX": "AS",
        "CY": "AS",
        "CZ": "EU",
        "DE": "EU",
        "DJ": "AF",
        "DK": "EU",
        "DM": "NA",
        "DO": "NA",
        "DZ": "AF",
        "EC": "SA",
        "EE": "EU",
        "EG": "AF",
        "EH": "AF",
        "ER": "AF",
        "ES": "EU",
        "ET": "AF",
        "EU": "EU",
        "FI": "EU",
        "FJ": "OC",
        "FK": "SA",
        "FM": "OC",
        "FO": "EU",
        "FR": "EU",
        "FX": "EU",
        "GA": "AF",
        "GB": "EU",
        "GD": "NA",
        "GE": "AS",
        "GF": "SA",
        "GG": "EU",
        "GH": "AF",
        "GI": "EU",
        "GL": "NA",
        "GM": "AF",
        "GN": "AF",
        "GP": "NA",
        "GQ": "AF",
        "GR": "EU",
        "GS": "AN",
        "GT": "NA",
        "GU": "OC",
        "GW": "AF",
        "GY": "SA",
        "HK": "AS",
        "HM": "AN",
        "HN": "NA",
        "HR": "EU",
        "HT": "NA",
        "HU": "EU",
        "ID": "AS",
        "IE": "EU",
        "IL": "AS",
        "IM": "EU",
        "IN": "AS",
        "IO": "AS",
        "IQ": "AS",
        "IR": "AS",
        "IS": "EU",
        "IT": "EU",
        "JE": "EU",
        "JM": "NA",
        "JO": "AS",
        "JP": "AS",
        "KE": "AF",
        "KG": "AS",
        "KH": "AS",
        "KI": "OC",
        "KM": "AF",
        "KN": "NA",
        "KP": "AS",
        "KR": "AS",
        "KW": "AS",
        "KY": "NA",
        "KZ": "AS",
        "LA": "AS",
        "LB": "AS",
        "LC": "NA",
        "LI": "EU",
        "LK": "AS",
        "LR": "AF",
        "LS": "AF",
        "LT": "EU",
        "LU": "EU",
        "LV": "EU",
        "LY": "AF",
        "MA": "AF",
        "MC": "EU",
        "MD": "EU",
        "ME": "EU",
        "MF": "NA",
        "MG": "AF",
        "MH": "OC",
        "MK": "EU",
        "ML": "AF",
        "MM": "AS",
        "MN": "AS",
        "MO": "AS",
        "MP": "OC",
        "MQ": "NA",
        "MR": "AF",
        "MS": "NA",
        "MT": "EU",
        "MU": "AF",
        "MV": "AS",
        "MW": "AF",
        "MX": "NA",
        "MY": "AS",
        "MZ": "AF",
        "NA": "AF",
        "NC": "OC",
        "NE": "AF",
        "NF": "OC",
        "NG": "AF",
        "NI": "NA",
        "NL": "EU",
        "NO": "EU",
        "NP": "AS",
        "NR": "OC",
        "NU": "OC",
        "NZ": "OC",
        "O1": "--",
        "OM": "AS",
        "PA": "NA",
        "PE": "SA",
        "PF": "OC",
        "PG": "OC",
        "PH": "AS",
        "PK": "AS",
        "PL": "EU",
        "PM": "NA",
        "PN": "OC",
        "PR": "NA",
        "PS": "AS",
        "PT": "EU",
        "PW": "OC",
        "PY": "SA",
        "QA": "AS",
        "RE": "AF",
        "RO": "EU",
        "RS": "EU",
        "RU": "EU",
        "RW": "AF",
        "SA": "AS",
        "SB": "OC",
        "SC": "AF",
        "SD": "AF",
        "SE": "EU",
        "SG": "AS",
        "SH": "AF",
        "SI": "EU",
        "SJ": "EU",
        "SK": "EU",
        "SL": "AF",
        "SM": "EU",
        "SN": "AF",
        "SO": "AF",
        "SR": "SA",
        "ST": "AF",
        "SV": "NA",
        "SY": "AS",
        "SZ": "AF",
        "TC": "NA",
        "TD": "AF",
        "TF": "AN",
        "TG": "AF",
        "TH": "AS",
        "TJ": "AS",
        "TK": "OC",
        "TL": "AS",
        "TM": "AS",
        "TN": "AF",
        "TO": "OC",
        "TR": "EU",
        "TT": "NA",
        "TV": "OC",
        "TW": "AS",
        "TZ": "AF",
        "UA": "EU",
        "UG": "AF",
        "UM": "OC",
        "US": "NA",
        "UY": "SA",
        "UZ": "AS",
        "VA": "EU",
        "VC": "NA",
        "VE": "SA",
        "VG": "NA",
        "VI": "NA",
        "VN": "AS",
        "VU": "OC",
        "WF": "OC",
        "WS": "OC",
        "YE": "AS",
        "YT": "AF",
        "ZA": "AF",
        "ZM": "AF",
        "ZW": "AF"
        }
        return dict_PaisAContinente[codigoPais]

def geolocalizarIP(ip):
        respuesta = {}
        try:
            respuesta = req.get("http://ip-api.com/json/" + str(ip)).json()
        except:
            respuesta = {'status': 'fail'}

        return respuesta

def obtenerContinenteIP(ip):
        infoGeolocalizacion = geolocalizarIP(ip)
        if infoGeolocalizacion['status'] != 'success':
            return ""
        else:
            return iso3166_Pais_A_Continente(geolocalizarIP(ip)['countryCode'])


def promediarRespuestas(respuestas):
    # almacenamos una tupla con (suma rtt, cantidad) por cada IP
    diccionarioIP = dict()
    for respuesta in respuestas:
        if respuesta[0] in diccionarioIP:
            valorAcumulado = diccionarioIP[respuesta[0]]
            diccionarioIP[respuesta[0]] = (valorAcumulado[0] + respuesta[1], valorAcumulado[1] + 1)
        else:
            diccionarioIP[respuesta[0]] = (respuesta[1], 1)

    cantidad_maxima = 0
    ip_elegida = None
    rtt_promedio = 0

    #revisamos todas las ips. Nos quedamos con aquella que aparece una mayor cantidad de veces. Tomamos de la misma, el promedio de los rtt.
    for ip in diccionarioIP.keys():
        if diccionarioIP[ip][1] > cantidad_maxima:
            cantidad_maxima = diccionarioIP[ip][1]
            ip_elegida = ip
            rtt_promedio = diccionarioIP[ip][0] / diccionarioIP[ip][1]

    return ip_elegida, rtt_promedio


def main(destino, maximo_ttl, timeout_por_ttl, mediciones_por_ttl, reintentos_por_ttl):
    #formateamos la dirección de destino
    destino = sp.Net(destino)
    #generamos un conjunto de paquetes ICMP, uno por cada ttl de 1 a maximo_ttl
    paquetes = sp.IP(dst=destino, ttl=(1, maximo_ttl)) / sp.ICMP()

    mediciones = []

    #para cada paquete (uno por cada ttl)
    for paquete in paquetes:
        paquete.getlayer(sp.ICMP).id = random.randint(0, 65535)
        #flag que indica si llegó alguna respuesta
        hubo_respuesta = False
        #flag para indicar si llegamos a destino
        llegamos_a_destino = False
        #array para almacenar las respuestas obtenidas
        respuestas = []
        for medicion in range(mediciones_por_ttl):
            for reintento in range(reintentos_por_ttl):
                #medimos el tiempo inicial
                t_inicial = time.perf_counter()
                #enviamos el paquete y obtenemos la respuesta
                respuesta = sp.sr1(paquete, verbose=0, timeout=timeout_por_ttl)
                #calculamos el rtt (tiempo final - tiempo inicial)
                rtt = time.perf_counter() - t_inicial

                hubo_respuesta = respuesta is not None

                if hubo_respuesta:
                    break
            #si obtuvimos una respuesta, la agregamos al conjunto de respuestas y chequeamos si el que respondió es nuestro destino
            if hubo_respuesta:
                ip_respuesta = respuesta.src
                respuestas.append((ip_respuesta, rtt))
                llegamos_a_destino = destino == ip_respuesta

        ip_salto, rtt_promedio = promediarRespuestas(respuestas)

        if ip_salto is None:
            print(("TTL: " + str(paquete.ttl) + ", Hop: *, RTT: *"))
        else:
            print(("TTL: " + str(paquete.ttl) + ", Hop: " + str(ip_salto) + ", RTT: " + str(int(rtt_promedio*1000)) + "ms") + " " + str(obtenerContinenteIP(ip_salto)))
            mediciones.append((paquete.ttl, ip_salto, rtt_promedio))

        if llegamos_a_destino:
            print("Destino alcanzado!")
            break

    outliers = detectarOutliers(mediciones)



if __name__ == "__main__":
    parametro_host_destino = "www.google.com"
    parametro_maximo_ttl = 20
    parametro_timeout_por_ttl = 0.3
    parametro_mediciones_por_ttl = 3
    parametro_intentos_por_ttl = 2

    if len(sys.argv) >= 2:
            parametro_host_destino = sys.argv[1]
    if len(sys.argv) >= 3:
            parametro_maximo_ttl = int(sys.argv[2])
    if len(sys.argv) >= 4:
            parametro_timeout_por_ttl = float(sys.argv[3])
    if len(sys.argv) >= 5:
            parametro_mediciones_por_ttl = int(sys.argv[4])
    if len(sys.argv) >= 6:
            parametro_intentos_por_ttl = int(sys.argv[5])

    if getuid() != 0:
        print('Ejecutar como admin')
        exit(1)

    main(parametro_host_destino, parametro_maximo_ttl, parametro_timeout_por_ttl, parametro_mediciones_por_ttl, parametro_intentos_por_ttl)
