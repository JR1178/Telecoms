// InfoFragment.kt
package com.example.networksurvey

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.telephony.CellInfoGsm
import android.telephony.TelephonyManager
import android.telephony.gsm.GsmCellLocation
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment

class InfoFragment : Fragment() {
    private lateinit var tm: TelephonyManager

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View = inflater.inflate(R.layout.fragment_info, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        tm = requireContext()
            .getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager

        // MCC / MNC
        val op = tm.networkOperator
        val mcc = if (op.length >= 3) op.substring(0,3) else "N/A"
        val mnc = if (op.length >= 3) op.substring(3) else "N/A"
        view.findViewById<TextView>(R.id.txtMcc).text = mcc
        view.findViewById<TextView>(R.id.txtMnc).text = mnc

        // IMEI (requires READ_PHONE_STATE)
        val imei = if (ContextCompat.checkSelfPermission(
                requireContext(), Manifest.permission.READ_PHONE_STATE
            ) == PackageManager.PERMISSION_GRANTED) {
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) tm.imei
                else tm.deviceId
            } catch (_: SecurityException) {
                "Restricted"
            }
        } else {
            "No Permission"
        } ?: "Unavailable"
        view.findViewById<TextView>(R.id.txtImei).text = imei

        // LAC (requires ACCESS_FINE_LOCATION)
        val lac = if(ContextCompat.checkSelfPermission(
                requireContext(), Manifest.permission.ACCESS_FINE_LOCATION
            ) == PackageManager.PERMISSION_GRANTED) {
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    val allCellInfo = tm.allCellInfo
                    val gsmCellInfo = allCellInfo.firstOrNull { it is CellInfoGsm } as? CellInfoGsm
                    gsmCellInfo?.cellIdentity?.lac?.toString() ?: "Unavailable1"
                } else {
                    val cL = tm.cellLocation
                    if (cL is GsmCellLocation) cL.lac.toString() else "Unavailable2"
                }

            } catch (_: SecurityException) {
                "Restricted"
            }
        } else {
            "No permission"
        }
        view.findViewById<TextView>(R.id.txtLac).text = lac

        // IMSI
        val imsi = try {
            tm.subscriberId
        } catch (sec: SecurityException) {
            "Restricted"
        } ?: "Unavailable"
        view.findViewById<TextView>(R.id.txtImsi).text = imsi
    }
}
