// ScreenSlidePagerAdapter.kt
package com.example.networksurvey

import androidx.fragment.app.Fragment
import androidx.fragment.app.FragmentActivity
import androidx.viewpager2.adapter.FragmentStateAdapter

class ScreenSlidePagerAdapter(fa: FragmentActivity)
    : FragmentStateAdapter(fa) {

    override fun getItemCount() = 2

    override fun createFragment(position: Int): Fragment =
        when (position) {
            0 -> InfoFragment()
            else -> SmsFragment()
        }
}
