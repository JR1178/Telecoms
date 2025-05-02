// SmsFragment.kt
package com.example.networksurvey

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.telephony.SmsManager
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment

class SmsFragment : Fragment() {
    private lateinit var editPhone: EditText
    private lateinit var editMsg: EditText

    // permission launcher
    private val requestSendSms = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) sendSms()
        else Toast.makeText(requireContext(),
            "SEND_SMS permission denied", Toast.LENGTH_SHORT).show()
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View = inflater.inflate(R.layout.fragment_sms, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        editPhone = view.findViewById(R.id.editPhone)
        editMsg   = view.findViewById(R.id.editMsg)
        view.findViewById<Button>(R.id.btnSend).setOnClickListener {
            // check/request permission
            if (ContextCompat.checkSelfPermission(
                    requireContext(), Manifest.permission.SEND_SMS
                ) == PackageManager.PERMISSION_GRANTED) {
                sendSms()
            } else {
                requestSendSms.launch(Manifest.permission.SEND_SMS)
            }
        }
    }

    private fun sendSms() {
        val phone = editPhone.text.toString().trim()
        val msg   = editMsg.text.toString().trim()
        if (phone.isEmpty() || msg.isEmpty()) {
            Toast.makeText(requireContext(),
                "Enter both number and message", Toast.LENGTH_SHORT).show()
            return
        }
        try {
            SmsManager.getDefault().sendTextMessage(phone, null, msg, null, null)
            Toast.makeText(requireContext(),
                "SMS sent", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(requireContext(),
                "Send failed: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }
}
