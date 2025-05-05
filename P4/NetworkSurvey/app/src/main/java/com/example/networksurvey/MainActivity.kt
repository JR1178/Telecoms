// MainActivity.kt
package com.example.networksurvey

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.viewpager2.widget.ViewPager2
import com.google.android.material.tabs.TabLayout
import com.google.android.material.tabs.TabLayoutMediator

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val viewPager = findViewById<ViewPager2>(R.id.view_pager)
        viewPager.adapter = ScreenSlidePagerAdapter(this)

        val tabs = findViewById<TabLayout>(R.id.tabs)
        TabLayoutMediator(tabs, viewPager) { tab, pos ->
            tab.text = when (pos) {
                0 -> "Info"
                else -> "SMS"
            }
        }.attach()
    }
}