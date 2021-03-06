/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */
package org.apache.isis.client.kroviz.ui.core

import io.kvision.core.CssSize
import io.kvision.core.UNIT
import io.kvision.dropdown.DropDown
import io.kvision.dropdown.ddLink
import io.kvision.dropdown.dropDown
import io.kvision.html.Button
import io.kvision.html.ButtonStyle
import io.kvision.navbar.*
import io.kvision.panel.SimplePanel
import io.kvision.panel.vPanel
import kotlinx.browser.window
import org.apache.isis.client.kroviz.core.event.EventStore
import org.apache.isis.client.kroviz.to.mb.Menubars
import org.apache.isis.client.kroviz.ui.panel.DropdownSearch
import org.apache.isis.client.kroviz.ui.dialog.About
import org.apache.isis.client.kroviz.ui.dialog.LoginPrompt
import org.apache.isis.client.kroviz.ui.panel.GeoMap
import org.apache.isis.client.kroviz.ui.chart.SampleChartModel
import org.apache.isis.client.kroviz.ui.dialog.SvgInline
import org.apache.isis.client.kroviz.ui.panel.EventChart
import org.apache.isis.client.kroviz.ui.panel.EventLogTable
import org.apache.isis.client.kroviz.ui.panel.SvgMap
import org.apache.isis.client.kroviz.utils.IconManager
import org.apache.isis.client.kroviz.utils.Point

object RoMenuBar : SimplePanel() {
    lateinit var navbar: Navbar
    private lateinit var nav: Nav

    init {
        vPanel {
            val label = "" //IMPROVE use for branding
            navbar = navbar(label = label, type = NavbarType.FIXEDTOP) {
                marginLeft = CssSize(-32, UNIT.px)
                height = CssSize(40, UNIT.px)
                nav = nav()
//                logoButton() leaves an empty space here without network connection
                val mainEntry = buildMainMenu()
                nav.add(mainEntry)
            }
        }
    }

    private fun buildMainMenu(): DropDown {
        return dropDown(
                "",
                icon = IconManager.find("Burger"),
                forNavbar = false,
                style = ButtonStyle.LIGHT)
        {
            ddLink(
                    "Connect ...",
                    icon = IconManager.find("Connect")
            ).onClick { e ->
                val at = Point(e.pageX.toInt(), e.pageY.toInt())
                LoginPrompt().open(at)
            }

            val toolTitle = "Toolbar"
            ddLink(toolTitle,
                    icon = IconManager.find(toolTitle)
            ).onClick {
                RoIconBar.toggle()
            }

            val sampleTitle = "History"
            ddLink(sampleTitle,
                    icon = IconManager.find(sampleTitle)
            ).onClick {
                val model = EventStore.log
                UiManager.add("Log Entries", EventLogTable(model))
            }

            val chartTitle = "Sample Chart"
            ddLink(chartTitle,
                    icon = IconManager.find("Chart")
            ).onClick {
                UiManager.add(chartTitle, EventChart(SampleChartModel()))
            }

            val geoMapTitle = "Sample Geo Map"
            ddLink(geoMapTitle,
                    icon = IconManager.find("Map")
            ).onClick {
                UiManager.add(geoMapTitle, GeoMap())
            }

            val svgMapTitle = "Sample SVG Map"
            ddLink(svgMapTitle,
                    icon = IconManager.find("Diagram")
            ).onClick {
                UiManager.add(svgMapTitle, SvgMap())
            }

            val svgInlineTitle = "Sample SVG Inline (interactive)"
            ddLink(svgInlineTitle,
                    icon = IconManager.find("Diagram")
            ).onClick {
                SvgInline().open()
            }

            val searchTitle = "Dropdown search example"
            ddLink(searchTitle,
                    icon = IconManager.find("Find")
            ).onClick {
                UiManager.add(searchTitle, DropdownSearch())
            }

            val aboutTitle = "About"
            ddLink(aboutTitle,
                    icon = IconManager.find(aboutTitle)
            ).onClick {
                About().open()
            }
        }
    }

    fun amendMenu(menuBars: Menubars) {
        logoButton()
        menuBars.primary.menu.forEach { m ->
            val dd = MenuFactory.buildForMenu(m)
            if (dd.getChildren().isNotEmpty()) nav.add(dd)
        }
        nav.add(MenuFactory.buildForMenu(menuBars.secondary.menu.first()))
        nav.add(MenuFactory.buildForMenu(menuBars.tertiary.menu.first()))
    }

    private fun logoButton() {
        val classes = setOf("logo-button-image", "logo-button")
        val logo = Button("", style = ButtonStyle.LINK, classes = classes)
                .onClick {
                    window.open("https://isis.apache.org")
                }
        nav.add(logo)
    }

}
